=== Stratos Payment Gateway ===
Contributors: justwallet                                 // OPTIONAL: Remove the entire line if you don't have one, or provide a valid URL.
Tags: payments, woocommerce, gateway, stratos, checkout, crypto, api
Requires at least: 5.0
Tested up to: 6.5.3                             // IMPORTANT: Update to the current WordPress version you tested with (e.g., 6.5.3)
Stable tag: 1.0.0                               // IMPORTANT: MUST match the Version in your stratos.php header exactly
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Stratos Payment Gateway for WooCommerce seamlessly integrates your online store with the Stratos Pay payment gateway, offering a secure and convenient payment experience for your customers.

== Description ==
Stratos Payment Gateway for WooCommerce seamlessly integrates your online store with the Stratos Pay payment gateway, offering a secure and convenient payment experience for your customers. By leveraging Stratos Pay's robust infrastructure, you can accept a wide range of payment options directly within your WooCommerce checkout flow, enhancing customer satisfaction and boosting conversion rates.

**Key Features:**

* **Seamless Integration:** Effortlessly integrates with your existing WooCommerce store.
* **Multiple Payment Methods:** Accept various payment options supported by Stratos Pay. (e.g., credit cards, crypto payments, mobile money, bank transfers, etc.)
* **Secure Transactions:** Process payments securely through Stratos Pay's encrypted gateway.
* **User-Friendly Checkout:** Provides a smooth and intuitive payment experience for your customers.
* **Real-time Notifications:** Get instant updates on transaction statuses via webhooks.
* **Full Refund Support:** Easily manage full refunds directly from your WooCommerce admin.

== Installation ==
### Standard Installation

1.  **Download** the plugin zip file from the WordPress Plugin Directory or your purchase source.
2.  **Navigate** to `Plugins > Add New` in your WordPress admin dashboard.
3.  Click the **"Upload Plugin"** button.
4.  **Choose** the downloaded `stratos-payment-gateway.zip` file and click "Install Now".
5.  **Activate** the plugin from the Plugins page.

### Manual Installation (via FTP)

1.  **Download** the plugin zip file.
2.  **Extract** the `stratos-payment-gateway` folder from the zip file.
3.  **Upload** the extracted `stratos-payment-gateway` folder to the `/wp-content/plugins/` directory on your server via FTP/SFTP.
4.  **Activate** the plugin from the `Plugins` page in your WordPress admin dashboard.

== Configuration ==
Once activated, you'll need to configure the Stratos Pay settings within WooCommerce.

1.  Go to `WooCommerce > Settings > Payments`.
2.  You will see "Stratos Pay" listed as an available gateway. Click **"Manage"** or **"Setup"**.
3.  **Enable/Disable:** Check the "Enable Stratos Pay" checkbox.
4.  **Title:** This is the name your customers will see on the checkout page (e.g., "Pay with Stratos Pay").
5.  **Description:** A brief description shown to customers on the checkout page.
6.  **Stratos Pay API Keys:**
    * **API Key:** Enter your Stratos API Key (obtainable from your Stratos Pay merchant dashboard).
    * **Account ID (Optional):** If provided, funds will go to a specific sub-account/wallet.
    * **Webhook Secret:** Enter the secret used to validate incoming webhooks from Stratos Pay.
7.  **Webhook URL:** The URL displayed here (`yourdomain.com/?wc-api=stratos_webhook`) needs to be configured in your Stratos Pay merchant dashboard for successful payment callbacks.
8.  Click **"Save Changes"**.


== Changelog ==
= 1.0.0 =
* Initial stable release.
* Integration with Stratos Pay API for payment processing.
* Webhook handling for real-time payment status updates.