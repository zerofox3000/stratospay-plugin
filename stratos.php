<?php

/**
 * Plugin Name: Stratos Payment Gateway
 * Plugin URI: https://stratospay.com/
 * Description: Accept payments via Stratos payment gateway for WooCommerce.
 * Version: 1.0.3  // Incremented version
 * Author: Stratos Pay
 * Author URI: https://stratospay.com
 * Text Domain: stratos-payment-gateway
 * Domain Path: /languages
 * WC requires at least: 5.0
 * WC tested up to: 8.9
 * Requires PHP: 7.4
 * WC-HPOS-Compatible: yes
 * License: GPLv2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

/**
 * Define a constant for the API base URL for easier environment switching.
 * You can define this in your wp-config.php for different environments:
 * define('STRATOS_PAY_API_BASE_URL', 'https://api.stratospay.com/v1');
 * If not defined, it will default to the live URL.
 */
if (!defined('STRATOS_PAY_API_BASE_URL')) {
    define('STRATOS_PAY_API_BASE_URL', 'https://stratospay.com/api/v1');
}

/**
 * Declare HPOS compatibility.
 * This should be done early, before WooCommerce initializes its features.
 */
add_action('before_woocommerce_init', function () {
    if (class_exists(\Automattic\WooCommerce\Utilities\FeaturesUtil::class)) {
        \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility('custom_order_tables', __FILE__, true);
    }
});

/**
 * Register custom order status for Stratos pending payments.
 * This makes it easier to query specifically for orders awaiting Stratos payment.
 */
function stratos_register_custom_order_status()
{
    register_post_status('wc-stratos-pending', [
        'label'                     => _x('Awaiting Stratos Payment', 'Order status', 'stratos-payment-gateway'),
        'public'                    => true,
        'exclude_from_search'       => false,
        'show_in_admin_all_list'    => true,
        'show_in_admin_status_list' => true,
        'label_count'               => _n_noop('Awaiting Stratos Payment (%s)', 'Awaiting Stratos Payment (%s)', 'stratos-payment-gateway'),
    ]);
}
add_action('init', 'stratos_register_custom_order_status');

/**
 * Add custom status to WooCommerce order statuses.
 */
function stratos_add_to_wc_order_statuses($order_statuses)
{
    $new_order_statuses = [];
    foreach ($order_statuses as $key => $status) {
        $new_order_statuses[$key] = $status;
        if ('wc-pending' === $key) { // Insert after 'pending'
            $new_order_statuses['wc-stratos-pending'] = _x('Awaiting Stratos Payment', 'Order status', 'stratos-payment-gateway');
        }
    }
    return $new_order_statuses;
}
add_filter('wc_order_statuses', 'stratos_add_to_wc_order_statuses');

/**
 * Add custom cron intervals.
 */
add_filter('cron_schedules', 'stratos_add_cron_intervals');
function stratos_add_cron_intervals($schedules)
{
    // Check if intervals already exist to prevent conflicts if another plugin adds them
    if (!isset($schedules['fifteen_minutes'])) {
        $schedules['fifteen_minutes'] = [
            'interval' => 900, // 15 * 60 = 900 seconds
            'display'  => __('Every 15 Minutes', 'stratos-payment-gateway'),
        ];
    }
    if (!isset($schedules['five_minutes'])) {
        $schedules['five_minutes'] = [
            'interval' => 300, // 5 * 60 = 300 seconds
            'display'  => __('Every 5 Minutes', 'stratos-payment-gateway'),
        ];
    }
    return $schedules;
}

/**
 * On plugin deactivation, unschedule the cron job.
 */
register_deactivation_hook(__FILE__, 'stratos_deactivate_plugin');
function stratos_deactivate_plugin()
{
    $timestamp = wp_next_scheduled('stratos_check_pending_payments');
    if ($timestamp) {
        wp_unschedule_event($timestamp, 'stratos_check_pending_payments');
    }
    // Also clear any recurring schedules just in case
    wp_clear_scheduled_hook('stratos_check_pending_payments');
}

/**
 * Initialize the Stratos Payment Gateway.
 */
function stratos_woocommerce_gateway_init()
{
    if (!class_exists('WC_Payment_Gateway')) {
        return; // WooCommerce Payment Gateway class not available
    }

    // Define the WC_Gateway_Stratos class if it doesn't already exist
    if (!class_exists('WC_Gateway_Stratos')) {
        class WC_Gateway_Stratos extends WC_Payment_Gateway
        {
            /**
             * @var string Stratos API Key.
             */
            public $api_key;

            /**
             * @var WC_Logger Instance of WC_Logger.
             */
            public $log;

            public $account_id;

            /**
             * Constructor for the gateway.
             */
            public function __construct()
            {
                $this->id                 = 'stratos';
                $this->icon               = plugins_url('assets/logo.jpg', __FILE__); // Ensure this path is correct
                $this->method_title       = __('Stratos Pay', 'stratos-payment-gateway');
                $this->method_description = __('Accept payments via Stratos payment gateway for WooCommerce.', 'stratos-payment-gateway');
                $this->has_fields         = false;
                $this->supports           = ['products', 'refunds']; // Added refunds support for future expansion

                // Load the settings.
                $this->init_form_fields();
                $this->init_settings();

                // Define user setting variables.
                $this->enabled            = $this->get_option('enabled');
                $this->title              = $this->get_option('title');
                $this->description        = $this->get_option('description');
                $this->account_id         = $this->get_option('account_id');
                $this->api_key            = $this->get_option('api_key');

                // Set up logging.
                $this->log = wc_get_logger();
                $this->log->debug('Stratos payment gateway loaded.', ['source' => $this->id]);

                // Hooks for admin options, API callback, and webhook.
                add_action('woocommerce_update_options_payment_gateways_' . $this->id, [$this, 'process_admin_options']);
                add_action('woocommerce_api_' . $this->id, [$this, 'handle_callback']); // For user redirection after payment attempt
                add_action('woocommerce_api_stratos_webhook', [$this, 'handle_webhook']); // For server-to-server notifications

                // Hook for the polling cron job
                add_action('stratos_check_pending_payments', [$this, 'check_pending_payments_cron']);

                // Schedule the cron job if it's not already scheduled
                $this->log->debug('Attempting to schedule cron job for stratos_check_pending_payments.', ['source' => $this->id]);
                if (!wp_next_scheduled('stratos_check_pending_payments')) {
                    $this->log->debug('Stratos cron job not found, scheduling now for five_minutes.', ['source' => $this->id]);
                    // Schedule to run every 5 minutes (adjust interval as needed: 'fifteen_minutes', 'hourly')
                    wp_schedule_event(time() + 300, 'five_minutes', 'stratos_check_pending_payments');
                } else {
                    $this->log->debug('Stratos cron job already scheduled.', ['source' => $this->id]);
                }
            }

            /**
             * Check if the gateway is available for use.
             *
             * @return bool
             */
            public function is_available()
            {
                $is_available = ('yes' === $this->enabled) && !empty($this->api_key);

                $this->log->debug(
                    sprintf(
                        __('Stratos Pay - is_available called. Enabled: %s, API Key present: %s, Result: %s', 'stratos-payment-gateway'),
                        $this->enabled,
                        !empty($this->api_key) ? __('Yes', 'stratos-payment-gateway') : __('No', 'stratos-payment-gateway'),
                        $is_available ? __('Available', 'stratos-payment-gateway') : __('Not Available', 'stratos-payment-gateway')
                    ),
                    ['source' => $this->id]
                );

                return $is_available;
            }

            /**
             * Handles incoming webhooks from Stratos Pay.
             */
            public function handle_webhook()
            {
                $payload = file_get_contents('php://input');
                $headers = getallheaders();
                $received_signature = $headers['Webhook-Secret'] ?? $headers['webhook-secret'] ?? ''; // Case-insensitive header check

                $secret = $this->get_option('webhook_secret');
                $computed_signature = hash_hmac('sha256', $payload, $secret);

                if (empty($secret) || empty($received_signature) || !hash_equals($computed_signature, $received_signature)) { // Use hash_equals for security
                    $this->log->warning('Stratos Pay Webhook: Unauthorized request or signature mismatch.', ['source' => $this->id, 'received_signature' => $received_signature, 'computed_signature' => $computed_signature]);
                    status_header(401);
                    echo 'Unauthorized webhook request.';
                    exit;
                }

                $data = json_decode($payload, true);

                if (json_last_error() !== JSON_ERROR_NONE || empty($data['event'])) {
                    $this->log->error('Stratos Pay Webhook: Invalid JSON or missing event in payload.', ['source' => $this->id, 'payload' => $payload, 'json_error' => json_last_error_msg()]);
                    status_header(400);
                    echo 'Invalid JSON';
                    exit;
                }

                $this->log->debug('Stratos webhook received: ' . print_r($data, true), ['source' => $this->id, 'event' => $data['event']]);

                if ($data['event'] === 'collection' && isset($data['data']['status'])) {
                    $external_id = sanitize_text_field($data['data']['external_reference'] ?? '');
                    $amount_received = (float)($data['data']['amount'] ?? 0) / 100;
                    $transaction_reference = sanitize_text_field($data['data']['transaction_reference'] ?? '');

                    // Find the order using YOUR `external_reference` that was sent during initiation.
                    $orders = wc_get_orders([
                        'limit'      => 1,
                        'meta_key'   => '_stratos_external_reference',
                        'meta_value' => $external_id,
                    ]);

                    if (empty($orders)) {
                        $this->log->warning(sprintf('Stratos Pay Webhook: No order found for external reference: %s', $external_id), ['source' => $this->id]);
                        status_header(200); // Always respond 200 to webhook even if order not found
                        exit;
                    }

                    $order = $orders[0];

                    if ($data['data']['status'] === 'success') {
                        // Verify the amount if necessary (highly recommended!)
                        // Use wc_format_decimal for precise comparison if currency conversion isn't an issue
                        if (wc_format_decimal($order->get_total(), 2) == wc_format_decimal($amount_received, 2)) {
                            // Use custom update logic here, similar to the cron job, since payment_complete is problematic.
                            if (!$order->has_status(wc_get_is_paid_statuses())) { // Prevent double completion
                                $order->set_transaction_id($transaction_reference);
                                $order->set_date_paid(time());
                                $order->set_status(apply_filters('woocommerce_payment_complete_order_status', $order->needs_processing() ? 'processing' : 'completed', $order->get_id()));
                                $order->save(); // Save the order after setting properties

                                wc_reduce_stock_levels($order->get_id()); // Reduce stock on success webhook
                                $order->add_order_note(sprintf(__('Stratos Pay webhook: Payment confirmed. Amount: %s. TXN ID: %s', 'stratos-payment-gateway'), wc_price($amount_received, ['currency' => $order->get_currency()]), $transaction_reference));
                                $this->log->info(sprintf('Stratos Pay webhook: Order #%s completed. External Ref: %s', $order->get_id(), $external_id), ['source' => $this->id]);
                            } else {
                                $this->log->info(sprintf('Stratos Pay webhook: Order #%s already paid. External Ref: %s', $order->get_id(), $external_id), ['source' => $this->id]);
                            }
                        } else {
                            $order->update_status('on-hold', sprintf(__('Stratos webhook: Amount mismatch. Expected: %s, Received: %s for external ref: %s', 'stratos-payment-gateway'), wc_price($order->get_total(), ['currency' => $order->get_currency()]), wc_price($amount_received, ['currency' => $order->get_currency()]), $external_id));
                            $this->log->warning(sprintf('Stratos Pay webhook: Amount mismatch for Order #%s. Expected: %s, Received: %s. External Ref: %s', $order->get_id(), wc_price($order->get_total(), ['currency' => $order->get_currency()]), wc_price($amount_received, ['currency' => $order->get_currency()]), $external_id), ['source' => $this->id]);
                        }
                    } else if ($data['data']['status'] === 'failed' || $data['data']['status'] === 'cancelled') {
                        if (!$order->has_status('failed') && !$order->has_status('cancelled')) { // Prevent redundant updates
                            $error_message = sanitize_text_field($data['data']['error_message'] ?? __('Payment cancelled or failed at gateway.', 'stratos-payment-gateway'));
                            $order->update_status('failed', sprintf(__('Stratos webhook: Payment failed. Details: %s', 'stratos-payment-gateway'), $error_message));
                            $order->add_order_note(sprintf(__('Stratos payment failed via webhook. Reason: %s', 'stratos-payment-gateway'), $error_message));
                            $this->log->warning(sprintf('Stratos Pay webhook: Order #%s marked failed. Reason: %s. External Ref: %s', $order->get_id(), $error_message, $external_id), ['source' => $this->id]);
                        }
                    }
                }

                status_header(200);
                echo 'Webhook received';
                exit;
            }


            /**
             * Admin Panel Options.
             * - Shows the settings in the admin page.
             */
            public function admin_options()
            {
?>
                <h2><?php echo esc_html($this->method_title); ?></h2>
                <p><?php echo esc_html($this->method_description); ?></p>

                <table class="form-table">
                    <?php $this->generate_settings_html(); ?>
                </table>
<?php
            }

            /**
             * Initialize Gateway Settings Form Fields.
             */
            public function init_form_fields()
            {
                $this->form_fields = [
                    'enabled' => [
                        'title'       => __('Enable/Disable', 'stratos-payment-gateway'),
                        'type'        => 'checkbox',
                        'label'       => __('Enable Stratos Pay', 'stratos-payment-gateway'),
                        'default'     => 'no',
                        'description' => __('Enable Stratos Pay to allow customers to pay with it.', 'stratos-payment-gateway'),
                    ],
                    'title' => [
                        'title'       => __('Title', 'stratos-payment-gateway'),
                        'type'        => 'text',
                        'description' => __('This controls the title which the user sees during checkout.', 'stratos-payment-gateway'),
                        'default'     => __('Stratos Pay', 'stratos-payment-gateway'),
                        'desc_tip'    => true,
                    ],
                    'description' => [
                        'title'       => __('Description', 'stratos-payment-gateway'),
                        'type'        => 'textarea',
                        'description' => __('This controls the description which the user sees during checkout.', 'stratos-payment-gateway'),
                        'default'     => __('Pay securely using Stratos Pay.', 'stratos-payment-gateway'),
                        'desc_tip'    => true,
                    ],
                    'account_id' => [
                        'title'       => __('Account ID', 'stratos-payment-gateway'),
                        'type'        => 'text',
                        'description' => __('Onboarded Customer ID, if this is provided, customer wallet will only be credited, funds won\'t go to main account wallet.', 'stratos-payment-gateway'),
                        'default'     => '', // Use empty string for default of text fields
                        'desc_tip'    => true,
                    ],
                    'api_key' => [
                        'title'       => __('API Key', 'stratos-payment-gateway'),
                        'type'        => 'password',
                        'description' => __('Enter your Stratos API Key. You can find this in your Stratos Pay dashboard.', 'stratos-payment-gateway'),
                        'default'     => '',
                        'desc_tip'    => true,
                        'placeholder' => __('sk_xxxxxxxxxxxxxxxxxxxxxx', 'stratos-payment-gateway'),
                    ],
                    'webhook_secret' => [
                        'title'       => __('Webhook Secret', 'stratos-payment-gateway'),
                        'type'        => 'text',
                        'description' => __('Secret used to validate incoming webhooks from Stratos Pay. Ensure its the same with secret added on Stratos Pay dashboard.', 'stratos-payment-gateway'),
                        'default'     => '',
                        'desc_tip'    => true,
                    ],
                    'webhook_url' => [
                        'title'       => __('Webhook URL', 'stratos-payment-gateway'),
                        'type'        => 'title', // This type just displays the value, not an input field
                        'description' => home_url('/wc-api/stratos_webhook'),
                    ],
                ];
            }

            /**
             * Output for the order received page.
             */
            public function payment_fields()
            {
                // Display the logo
                echo '<p><img src="' . esc_url($this->icon) . '" style="height: 100px; max-width: 100%; margin-bottom: 10px;" alt="' . esc_attr($this->method_title) . '" /></p>';
                // Display the description
                if ($this->description) {
                    echo wpautop(wp_kses_post($this->description));
                }
            }

            /**
             * Process the payment and return the result.
             *
             * @param int $order_id
             * @return array
             */
            public function process_payment($order_id)
            {
                $order = wc_get_order($order_id);

                if (!$order) {
                    $this->log->error('Stratos Pay - Process payment called for non-existent order ID: ' . $order_id, ['source' => $this->id]);
                    wc_add_notice(__('Error: Invalid order for payment processing.', 'stratos-payment-gateway'), 'error');
                    return ['result' => 'fail'];
                }

                // IMPORTANT: If the order is already in a "paid" status, don't try to process payment again.
                if ($order->has_status(wc_get_is_paid_statuses())) {
                    $this->log->debug('Stratos Pay - Process payment called for already paid Order ID: ' . $order_id . '. Redirecting to thank you page.', ['source' => $this->id]);
                    return [
                        'result'   => 'success',
                        'redirect' => $this->get_return_url($order),
                    ];
                }

                // Use a transient lock to prevent immediate double submission for this order ID
                $lock_key = 'stratos_payment_lock_' . $order_id;
                if (get_transient($lock_key)) {
                    $this->log->warning('Stratos Pay - Payment processing already in progress for Order ID: ' . $order_id . '. Aborting duplicate call.', ['source' => $this->id]);
                    wc_add_notice(__('Payment is already being processed for this order. Please wait or try again.', 'stratos-payment-gateway'), 'notice');
                    return [
                        'result' => 'fail',
                    ];
                }
                set_transient($lock_key, true, 5); // Lock for 5 seconds

                // Generate a NEW unique external reference for EACH payment initiation attempt
                $external_reference = uniqid('stratos_wc_', true);

                $payload = [
                    'customer' => [
                        'first_name' => $order->get_billing_first_name(),
                        'last_name'  => $order->get_billing_last_name(),
                        'email'      => $order->get_billing_email(),
                        'ip_address' => WC_Geolocation::get_ip_address(),
                    ],
                    'billing_address' => [
                        'country'     => $order->get_billing_country(),
                        'state'       => $order->get_billing_state(),
                        'city'        => $order->get_billing_city(),
                        'address'     => $order->get_billing_address_1(),
                        'postal_code' => $order->get_billing_postcode(),
                    ],
                    'amount'             => (string) (wc_format_decimal($order->get_total(), 2) * 100),
                    'currency'           => $order->get_currency(),
                    'title'              => sprintf(__('Order #%s', 'stratos-payment-gateway'), $order->get_id()),
                    'description'        => sprintf(__('WooCommerce Order #%s', 'stratos-payment-gateway'), $order->get_id()),
                    'external_reference' => $external_reference, // This is the new unique reference for this attempt
                    'callback_url'       => add_query_arg(
                        [
                            'wc-api'   => $this->id,
                            'order_id' => $order->get_id(),
                            'ref'      => $external_reference, // Pass the NEW external reference
                        ],
                        home_url('/')
                    ),
                ];

                if ($this->account_id) {
                    $payload['account_id'] = $this->account_id;
                }

                $api_endpoint = STRATOS_PAY_API_BASE_URL . '/payment'; // Assuming this is the correct payment initiation endpoint

                $this->log->debug('Stratos Pay - Sending payment initiation request for Order #' . $order->get_id(), ['source' => $this->id, 'payload' => $payload]);

                $response = wp_remote_post($api_endpoint, [
                    'headers' => [
                        'Authorization' => 'Bearer ' . $this->api_key,
                        'Content-Type'  => 'application/json',
                    ],
                    'body'    => wp_json_encode($payload),
                    'timeout' => 45, // Increased timeout for potentially slow API responses
                ]);

                // Clear the transient lock after API call (whether successful or not)
                delete_transient($lock_key);

                $this->log->debug('Stratos Pay - Payment initiation API response status: ' . wp_remote_retrieve_response_code($response), ['source' => $this->id, 'response_raw' => wp_remote_retrieve_body($response)]);

                if (is_wp_error($response)) {
                    $error_message = $response->get_error_message();
                    $this->log->error('Stratos Pay - API request failed: ' . $error_message, ['source' => $this->id]);
                    wc_add_notice(sprintf(__('Payment initialization failed: %s', 'stratos-payment-gateway'), $error_message), 'error');
                    return ['result' => 'fail'];
                }

                $response_code = wp_remote_retrieve_response_code($response);
                $body = wp_remote_retrieve_body($response);
                $parsed_body = json_decode($body, true);

                if ($response_code !== 200 || empty($parsed_body['data']['checkout_url'])) {
                    $error_message = __('Payment failed.', 'stratos-payment-gateway');
                    if (!empty($parsed_body['message'])) {
                        if (is_array($parsed_body['message'])) {
                            // Concatenate array messages for user-friendly output
                            $messages = [];
                            foreach ($parsed_body['message'] as $field => $msgs) {
                                $messages[] = ucfirst($field) . ': ' . implode(', ', (array) $msgs);
                            }
                            $error_message = implode(' | ', $messages);
                        } else {
                            $error_message = $parsed_body['message'];
                        }
                    }
                    $this->log->error('Stratos Pay - API error message: ' . $error_message . ' | Response Code: ' . $response_code . ' | Body: ' . $body, ['source' => $this->id]);
                    wc_add_notice(sprintf(__('Payment initialization failed. Error from gateway: %s', 'stratos-payment-gateway'), $error_message), 'error');
                    return ['result' => 'fail'];
                }

                // Store the external reference for this specific payment attempt.
                // This is crucial for webhook and callback verification.
                $order->update_meta_data('_stratos_external_reference', $external_reference);
                // Optionally store Stratos's own transaction ID if they provide it immediately.
                // $order->update_meta_data('_stratos_txn_id_initial', $parsed_body['data']['transaction_reference'] ?? '');
                $order->save();

                // Set order status to awaiting Stratos payment
                $order->update_status('stratos-pending', __('Awaiting payment confirmation from Stratos Pay.', 'stratos-payment-gateway'));

                // Stock levels are reduced only on successful payment confirmation (webhook/polling).
                // wc_reduce_stock_levels($order_id);

                // Return success and redirect to checkout URL.
                return [
                    'result'   => 'success',
                    'redirect' => $parsed_body['data']['checkout_url'],
                ];
            }

            /**
             * Handle Stratos callback after user returns from Stratos Pay.
             * This is often for user-facing feedback, webhook is preferred for definitive status updates.
             */
            public function handle_callback()
            {
                // Verify necessary parameters.
                $order_id           = sanitize_text_field($_GET['order_id'] ?? null);
                $received_external_reference = sanitize_text_field($_GET['ref'] ?? null);

                if (empty($order_id) || empty($received_external_reference)) {
                    $this->log->warning('Stratos Pay - Callback received with missing order_id or external_reference.', ['source' => $this->id, 'GET' => $_GET]);
                    status_header(400); // Bad Request
                    exit;
                }

                $order = wc_get_order($order_id);
                if (!$order) {
                    $this->log->error('Stratos Pay - Callback received for non-existent order ID: ' . $order_id, ['source' => $this->id, 'GET' => $_GET]);
                    status_header(404); // Not Found
                    exit;
                }

                // Verify the external reference against the stored one to prevent tampering.
                // This ensures the callback is for a payment attempt we initiated for this order.
                $stored_external_reference = $order->get_meta('_stratos_external_reference', true);
                if ($stored_external_reference !== $received_external_reference) {
                    $this->log->warning(
                        sprintf(
                            __('Stratos Pay - Callback external reference mismatch for Order #%s. Expected: %s, Received: %s', 'stratos-payment-gateway'),
                            $order->get_id(),
                            $stored_external_reference,
                            $received_external_reference
                        ),
                        ['source' => $this->id, 'GET' => $_GET]
                    );
                    status_header(403); // Forbidden
                    exit;
                }

                // If the order is already in a paid status, just redirect to thank you page.
                // This prevents redundant API calls if webhook already processed it.
                if ($order->has_status(wc_get_is_paid_statuses())) {
                    $this->log->info(sprintf('Stratos Pay callback: Order #%s already paid, redirecting.', $order->get_id()), ['source' => $this->id]);
                    wp_redirect($this->get_return_url($order));
                    exit;
                }

                // Verify payment status with Stratos API
                $verify_url = STRATOS_PAY_API_BASE_URL . '/verify-payment/' . $received_external_reference;

                $this->log->debug('Stratos Pay - Verifying payment for Order #' . $order->get_id() . ' with URL: ' . $verify_url . ' (External Ref: ' . $received_external_reference . ')', ['source' => $this->id]);

                $response = wp_remote_get($verify_url, [
                    'timeout' => 30,
                    'headers' => [
                        'Authorization' => 'Bearer ' . $this->api_key,
                        'Accept'        => 'application/json',
                    ],
                ]);

                if (is_wp_error($response)) {
                    $error_message = $response->get_error_message();
                    $this->log->error('Stratos Pay - Verification API request failed: ' . $error_message, ['source' => $this->id]);
                    wc_add_notice(sprintf(__('Payment verification failed: %s', 'stratos-payment-gateway'), $error_message), 'error');
                    wp_redirect($order->get_checkout_payment_url(true)); // Redirect to payment page with error
                    exit;
                }

                $body = json_decode(wp_remote_retrieve_body($response), true);
                $response_code = wp_remote_retrieve_response_code($response);

                if ($response_code === 200 && isset($body['status']) && $body['status'] === 'success' && isset($body['data']['status']) && ($body['data']['status'] === 'success' || $body['data']['status'] === 'onchain')) {
                    // Payment is successful
                    if (!$order->has_status(wc_get_is_paid_statuses())) {
                        $transaction_id = $body['data']['transaction_reference'] ?? '';

                        // Replicating payment_complete actions explicitly
                        $order->set_transaction_id($transaction_id);
                        $order->set_date_paid(time());
                        // Determine the appropriate status (processing or completed)
                        $status_to_set = $order->needs_processing() ? 'processing' : 'completed';
                        $order->set_status(apply_filters('woocommerce_payment_complete_order_status', $status_to_set, $order->get_id()));
                        $order->save(); // Explicitly save the order

                        wc_reduce_stock_levels($order->get_id()); // Reduce stock on success
                        $order->add_order_note(sprintf(__('Stratos Pay callback: Payment successfully completed. TXN ID: %s', 'stratos-payment-gateway'), $transaction_id));
                        $this->log->info(sprintf('Stratos Pay callback: Order #%s payment completed. TXN ID: %s', $order->get_id(), $transaction_id), ['source' => $this->id]);
                    } else {
                        $this->log->info(sprintf('Stratos Pay callback: Order #%s is already paid. Skipping status update.', $order->get_id()), ['source' => $this->id]);
                    }
                } else {
                    $error_details = isset($body['message']) ? $body['message'] : __('Unknown verification error.', 'stratos-payment-gateway');
                    $this->log->error(
                        sprintf(
                            __('Stratos Pay callback: Payment verification failed for Order #%s. Response Code: %s, Body: %s', 'stratos-payment-gateway'),
                            $order->get_id(),
                            $response_code,
                            wp_json_encode($body)
                        ),
                        ['source' => $this->id]
                    );
                    $order->update_status('failed', sprintf(__('Stratos Pay callback: Payment verification failed. Details: %s', 'stratos-payment-gateway'), $error_details));
                    wc_add_notice(sprintf(__('Payment verification failed. Please try again or contact support. Details: %s', 'stratos-payment-gateway'), $error_details), 'error');
                }

                wp_redirect($this->get_return_url($order));
                exit;
            }

            /**
             * WP-Cron function to check pending Stratos payments.
             */
            public function check_pending_payments_cron()
            {
                $this->log->debug('Stratos Pay - Running cron job to check pending payments.', ['source' => $this->id]);
                // --- END Webhook.site monitoring code ---

                // Get orders that are 'wc-stratos-pending' (your custom status)
                // Limit to orders that were placed within the last 48 hours to prevent checking very old orders indefinitely.
                $orders = wc_get_orders([
                    'status'       => 'stratos-pending',
                    'limit'        => 50, // Process a batch to prevent timeouts on many orders
                    'orderby'      => 'date',
                    'order'        => 'ASC', // Oldest first
                    'date_created' => '>=' . (time() - DAY_IN_SECONDS * 14), // Check orders created in the last 7 days (1 week)
                    'meta_key'     => '_stratos_external_reference', // Must have an external reference
                    'meta_compare' => 'EXISTS',
                ]);

                if (empty($orders)) {
                    $this->log->debug('Stratos Pay - No pending Stratos payments found for cron check.', ['source' => $this->id]);
                    return;
                }

                $chunk_size = 10;
                $order_chunks = array_chunk($orders, $chunk_size);
                foreach ($order_chunks as $chunk_number => $chunk_of_orders) {
                    foreach ($chunk_of_orders as $order) {
                        $order_id = $order->get_id();
                        $external_reference = $order->get_meta('_stratos_external_reference', true);

                        // Skip if no external reference or already paid/failed/cancelled
                        if (empty($external_reference) || $order->has_status(wc_get_is_paid_statuses()) || $order->has_status('failed') || $order->has_status('cancelled')) {
                            $this->log->debug(sprintf('Stratos Pay - Skipping cron check for Order #%s (Status: %s, External Ref: %s)', $order_id, $order->get_status(), $external_reference), ['source' => $this->id]);
                            continue;
                        }

                        $verify_url = STRATOS_PAY_API_BASE_URL . '/verify-payment/' . $external_reference;

                        $this->log->debug('Stratos Pay - Polling for Order #' . $order_id . ' (External Ref: ' . $external_reference . ')', ['source' => $this->id]);

                        $response = wp_remote_get($verify_url, [
                            'timeout' => 30,
                            'headers' => [
                                'Authorization' => 'Bearer ' . $this->api_key,
                                'Accept'        => 'application/json',
                            ],
                        ]);

                        if (is_wp_error($response)) {
                            $error_message = $response->get_error_message();
                            $this->log->error(sprintf('Stratos Pay - Polling API request failed for Order #%s: %s', $order_id, $error_message), ['source' => $this->id]);
                            continue; // Move to the next order
                        }

                        $body = json_decode(wp_remote_retrieve_body($response), true);
                        $response_code = wp_remote_retrieve_response_code($response);

                        if ($response_code === 200 && isset($body['status']) && $body['data']['status'] === 'success' && ($body['data']['status'] === 'success' || $body['data']['status'] === 'onchain')) {
                            // Payment is successful
                            if (!$order->has_status(wc_get_is_paid_statuses())) {
                                $transaction_id = $body['data']['transaction_reference'] ?? '';

                                $this->log->debug(sprintf('Stratos Pay polling: Attempting manual payment completion for Order #%s with TXN ID: %s. Current status: %s', $order_id, $transaction_id, $order->get_status()), ['source' => $this->id]);

                                // --- Manual payment completion actions ---
                                $order->set_transaction_id($transaction_id);
                                $order->set_date_paid(time());
                                // Determine the appropriate status (processing or completed)
                                $status_to_set = $order->needs_processing() ? 'processing' : 'completed';
                                $order->set_status(apply_filters('woocommerce_payment_complete_order_status', $status_to_set, $order->get_id()));
                                $order->save(); // Explicitly save the order after setting properties
                                // --- End manual payment completion actions ---

                                wc_reduce_stock_levels($order->get_id()); // Reduce stock on success
                                $order->add_order_note(sprintf(__('Stratos Pay polling: Payment confirmed. TXN ID: %s', 'stratos-payment-gateway'), $transaction_id));
                                $this->log->info(sprintf('Stratos Pay polling: Order #%s payment completed. TXN ID: %s. Final status: %s', $order_id, $transaction_id, $order->get_status()), ['source' => $this->id]); // Log final status
                            } else {
                                $this->log->info(sprintf('Stratos Pay polling: Order #%s already paid, confirmed. Skipping status update.', $order_id), ['source' => $this->id]);
                            }
                        } else {
                            // Payment is not yet successful or has failed.
                            // Check for explicit failure status from Stratos
                            if (isset($body['data']['status']) && ($body['data']['status'] === 'failed' || $body['data']['status'] === 'cancelled')) {
                                $error_details = isset($body['message']) ? $body['message'] : __('Unknown verification error during polling.', 'stratos-payment-gateway');
                                if (!$order->has_status('failed') && !$order->has_status('cancelled')) { // Prevent redundant updates
                                    $order->update_status('failed', sprintf(__('Stratos Pay polling: Payment marked failed. Details: %s', 'stratos-payment-gateway'), $error_details));
                                    $order->add_order_note(sprintf(__('Stratos payment failed via polling. Reason: %s', 'stratos-payment-gateway'), $error_details));
                                    $this->log->warning(sprintf('Stratos Pay polling: Order #%s payment failed. Reason: %s', $order_id, $error_details), ['source' => $this->id]);
                                }
                            } else {
                                // Payment is still pending/processing. Do nothing for now, it will be checked again.
                                $this->log->debug(sprintf('Stratos Pay polling: Order #%s payment still pending. Current status: %s', $order_id, $body['data']['status'] ?? 'N/A'), ['source' => $this->id]);
                            }
                        }
                    }
                    sleep(1); // Pause for 1 second between chunks
                }
                $this->log->debug('Stratos Pay - Finished cron job for pending payments.', ['source' => $this->id]);
            }
        } // End of WC_Gateway_Stratos class definition
    } // End of if (!class_exists('WC_Gateway_Stratos'))

    /**
     * Add the Stratos Gateway to WooCommerce.
     *
     * @param array $methods
     * @return array
     */
    function stratos_add_woocommerce_gateway($methods)
    {
        $methods[] = 'WC_Gateway_Stratos';
        return $methods;
    }

    add_filter('woocommerce_payment_gateways', 'stratos_add_woocommerce_gateway');

    // IMPORTANT: Instantiate the gateway class here to ensure its __construct method
    // runs early enough to register all its action hooks (including the cron hook),
    // even if the payment gateways list isn't fully processed yet.
    new WC_Gateway_Stratos();
} // End of stratos_woocommerce_gateway_init

add_action('plugins_loaded', 'stratos_woocommerce_gateway_init');
