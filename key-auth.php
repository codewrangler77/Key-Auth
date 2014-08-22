<?php
/**
 * Plugin Name: JSON API Key Authentication
 * Description: API/Secret Key Authentication handler for the JSON API
 * Author: Paul Hughes and WP API Team
 * Author URI: https://github.com/WP-API
 * Version: 0.1
 * Plugin URI: https://github.com/WP-API/Key-Auth
 */

/**
 * Checks the HTTP request and authenticates a user using an API key and shared secret.
 *
 * @param mixed $user The current user passed in the filter.
 */

class JSON_Key_Auth {

	/**
	 * The primary handler for user authentication.
	 *
	 * @param mixed $user The current user (or bool) passing through the filter.
	 * @return mixed A user on success, or false on failure.
	 * @author Paul Hughes
	 */
	public static function authHandler( $user ) {
		// Don't authenticate twice
		if ( ! empty( $user ) ) {
			return $user;
		}

		if ( !isset( $_SERVER['HTTP_X_API_KEY'] ) || !isset( $_SERVER['HTTP_X_API_TIMESTAMP'] ) || !isset( $_SERVER['HTTP_X_API_SIGNATURE'] ) ) {
			return $user;
		}

		$user_id = self::findUserIdByKey( $_SERVER['HTTP_X_API_KEY'] );
		$user_secret = get_user_meta( $user_id, 'json_shared_secret' );

		// Check for the proper HTTP Parameters
		$signature_args = array(
			'api_key' => $_SERVER['HTTP_X_API_KEY'],
			'timestamp' => $_SERVER['HTTP_X_API_TIMESTAMP'],
			'request_method' => $_SERVER['REQUEST_METHOD'],
			'request_uri' => $_SERVER['REQUEST_URI'],
		);

		$signature_gen = self::generateSignature( $signature_args, $user_secret );
		$signature = $_SERVER['HTTP_X_API_SIGNATURE'];

		if ( $signature_gen != $signature ) {
			return false;
		}

		return $user_id;
	}

	/**
	 * @param array $args The arguments used for generating the signature. They should be, in order:
	 *                    'api_key', 'timestamp', 'request_method', and 'request_uri'.
	 *                    Timestamp should be the timestamp passed in the reques.
	 * @param string $secret The shared secret we are using to generate the hash.
	 * @return string
	 */
	public static function generateSignature( $args, $secret ) {
		return md5( json_encode( $args ) . $secret );
	}

	/**
	 * Fetches a user ID by API key.
	 *
	 * @param string $api_key The API key attached to a user.
	 * @return bool
	 */
	public static function findUserIdByKey( $api_key ) {
		$user_args = array(
			'meta_query' => array(
				array(
					'key' => 'json_api_key',
					'value' => $api_key,
				),
			),
			'number' => 1,
			'fields' => array( 'ID' ),
		);
		$user = get_users( $user_args );
		if ( is_array( $user ) && !empty( $user ) ) {
			return $user[0]->ID;
		}

		return false;
	}
}

add_filter( 'determine_current_user', array( 'JSON_Key_Auth', 'authHandler' ), 20 );

/* ----------------------------------------------------------- *
 * Be able to generate an API key and shared secret for a user
 * ----------------------------------------------------------- */



function jsrk_show_user_api_fields( $user ) { ?>

	<h3>API Authentication</h3>

	<table class="form-table">

		<tr>
			<th><label for="apikey">API Key</label></th>

			<td>
				<input type="text" name="jsrk_apikey" id="jsrka-apikey" value="<?php echo get_user_meta( $user->ID, 'json_api_key', TRUE); ?>" class="regular-text" /> <input type="button" class="button button-secondary" value="Generate" onclick="jsonRestKeyAuth.generateAPIKeyToField($('#jsrka-apikey')); return false;"><br />
			</td>
		</tr>
		<tr>
			<th><label for="apiSecret">Shared Secret</label></th>

			<td>
				<input type="text" name="jsrk_shared_secret" id="jsrka-apisecret" value="" class="regular-text" /><input type="button" class="button button-secondary" value="Generate" onclick="jsonRestKeyAuth.generateSharedSecret($('#jsrka-apisecret')); return false;"><br />
			</td>
		</tr>

	</table>
<?php }

add_action( 'show_user_profile', 'jsrk_show_user_api_fields' );
add_action( 'edit_user_profile', 'jsrk_show_user_api_fields' );

function jsrk_save_extra_profile_fields( $user_id ) {

	if ( !current_user_can( 'edit_user', $user_id ) )
		return false;

	update_user_meta( $user_id, 'json_api_key', $_POST['jsrk_apikey'] );
	update_user_meta( $user_id, 'json_shared_secret', $_POST['jsrk_shared_secret'] );
}

add_action( 'personal_options_update', 'jsrk_save_extra_profile_fields' );
add_action( 'edit_user_profile_update', 'jsrk_save_extra_profile_fields' );

function key_auth_scripts($hook) {

	if( 'profile.php' != $hook )
		return;

	wp_enqueue_script( 'json-rest-key-auth', plugin_dir_url( __FILE__ ) . '/js/json-rest-key-auth.js', array(), '1.0.0', true );
}

add_action( 'admin_enqueue_scripts', 'key_auth_scripts' );
