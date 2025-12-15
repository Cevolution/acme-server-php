<?php namespace cevolution\ciam {
    use \Lcobucci\JWT\Token;
	use \Lcobucci\JWT\Token\Parser;
	use \Lcobucci\JWT\Encoding\JoseEncoder;
	use \Lcobucci\JWT\Signer\Rsa\Sha256 as RsSigner;
	use \Lcobucci\JWT\Validation\Validator as JWTValidator;
	use \Lcobucci\JWT\Validation\Constraint;
	use \Lcobucci\JWT\Signer\Key;

	use \Lcobucci\Clock\SystemClock;

	use League\OAuth2\Client\Provider\AbstractProvider;	

if (!class_exists(__NAMESPACE__ . '\API')) {
	require_once __DIR__ . '/./vendor/autoload.php';

	abstract class API {
		//	API Authority path
		private string $authority;

		//	Cached Bearer JWT
		private ?string $jwt = null;

		//	Cached JWT Parser
		private ?Parser $parser = null;

		//	Cached Mediated Bearer Token
		private ?string $_Bearer_ = null;

		//	Cached Mediated Bearer Refresh Token
		private ?string $_Bearer__ = null;

		//	Cached Decoded Bearer Token Scopes
		private ?array $scopes = null;

		//	Cached Decoded Bearer Token
		private ?Token\Plain $token = null;

		abstract protected function jwks(): array;

		abstract protected function issuer(): Constraint\IssuedBy;

		abstract protected function provider(): AbstractProvider;

		abstract protected function redirect(): void;

		/**
         * This function will resolve the token for the supplied JWT whilst at the same time
         * ensuring that the token is valid (i.e. not expired and signed with the correct key).
         * It will also resolve the mediated Bearer Token, if applicable, additionally ensuring
         * that it's valid and refreshed if needed. The function also populates the majority
         * of the cached information used by the other methods in this class.
         *
         * @param string|null $jwt
         * @return Token\Plain|null
         * @throws \Exception
         */
		protected function token(string | null $jwt = null): Token\Plain | null {
			if ($jwt)
			try {
				$this->parser = $this->parser ?? new Parser(new JoseEncoder());

				$token = $this->parser->parse($jwt);

				if ($token instanceof Token\Plain) {
					$jwks = $this->jwks();

					$issuer = $this->issuer();

					$kid = $token->headers()->get('kid', 0);

					$key = $jwks[$kid] ?? "";

					// Token Validated?
					$validator = new JWTValidator();
					$validator->assert($token, $issuer);
					$validator->assert($token, new Constraint\SignedWith(new RsSigner(), Key\InMemory::plainText($key)));
					$validator->assert($token, new Constraint\LooseValidAt(
						SystemClock::fromUTC(),
						new \DateInterval('PT5S')	// 5 Second leeway
					));

					// Update cached token information
					$this->scopes = preg_split('/\s+/', trim($token->claims()->get('scope', '')));
					$this->token = $token;
					$this->jwt = $jwt;

					// Enpoint mediated token checking?
					if (in_array('endpoint:mediate', $this->scopes, true)) {
						// Get subject for mediated token checking
						$sub = $token->claims()->get('sub');

						// Does the user have a mediated Bearer Token in the Cookie?
						$_jwt = $this->_Bearer_ ?? $_COOKIE['_Bearer_' . $sub] ?? null;
						if ($_jwt && !empty($_jwt) && $_jwt !== $jwt)
						try {
							// Whilst the various cookie expiry and protection mechanisms should ensure
							// that the token is valid, we still validate the JWT to ensure that
							// the mediated token is valid (e.g. has not expired).
							$token = $this->parser->parse($_jwt);

							if ($token instanceof Token\Plain) {
								// Mediated Token must be signed from the same key set
								$kid = $token->headers()->get('kid', 0);

								$key = $jwks[$kid] ?? "";

								// Token Validated?
								$validator->assert($token, $issuer);
								$validator->assert($token, new Constraint\SignedWith(new RsSigner(), Key\InMemory::plainText($key)));
								$validator->assert($token, new Constraint\LooseValidAt(SystemClock::fromUTC()));

								// Update cached token information
								$this->scopes = preg_split('/\s+/', trim($token->claims()->get('scope', '')));
								$this->token = $token;
								$this->jwt = $_jwt;

								return $token;
							}
						// https://lcobucci-jwt.readthedocs.io/en/stable/validating-tokens/#using-lcobuccijwtvalidatorassert
						} catch (\Lcobucci\JWT\Validation\RequiredConstraintsViolated $exception) {
/*							
							Log::Instance()->error($exception->getMessage(), [
								'section' => __METHOD__ . ' L:' . __LINE__,
								'error' => new \WP_Error(
									$exception->getCode() || 401,
									$exception->getMessage())
							]);
*/							
						}

						// Is there a Refresh Token we can use?
						$__jwt = $this->_Bearer__ = $this->_Bearer__ ?? $_COOKIE['_Bearer__' . $sub] ?? null;

						if ($__jwt && !empty($__jwt) && $_jwt !== $jwt) {
							$home_url = home_url();

							$parsed_url = parse_url($home_url);

							$host = $parsed_url['host'];

							//	Resolve immediate path parent and structure so that cookies are resolved
							//  hierarchically.
							//
							$parent = $parsed_url['path'] . '/wp-json' . $this->authority . '/';

							try {
								$provider = $this->provider();

								// Refresh the mediated token using the Refresh Token
								$result = $provider->getAccessToken('refresh_token', [
									'refresh_token' => $__jwt
								]);

								//  Once the token has been obtained set the relevant cookies against the
								//  associated path. User the 'sub' claim as part of the cookie name to ensure
								//  verifiable uniqueness. Also prefix in a way that aligns with best practices:
								//  https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-20
								//
								setcookie('_Bearer_' . $sub,
									$this->_Bearer_ = $result?->getToken() ?? "", [
										'expires' => $result?->getExpires() ?? time() + 3600,
										'path' => $parent,
										'domain' => $host,
										'secure' => is_ssl() ? true : false,
										'httpOnly' => true,
										'sameSite' => 'Strict'
								]);
								setcookie('_Bearer__' . $sub,
									$this->_Bearer__ = $result?->getRefreshToken() ?? $this->_Bearer__ ?? "", [
										'path' => $parent,
										'domain' => $host,
										'secure' => is_ssl() ? true : false,
										'httpOnly' => true,
										'sameSite' => 'Strict'
								]);

								// Update cached token information
								return($this->token($this->_Bearer_));
	//							$this->token = $this->parser->parse($this->__Bearer_ ?? '');
	//							$this->scopes = null;
	//							$this->jwt = $this->__Bearer_;
							}  catch (\Exception $exception) {
								// Clear cookies on error
								setcookie('_Bearer_' . $sub, "", [
									'expires' => time() - 3600,
									'path' => $parent,
									'domain' => $host,
									'secure' => is_ssl() ? true : false,
									'httpOnly' => true,
									'sameSite' => 'Strict'
								]);

								setcookie('_Bearer__' . $sub, "", [
									'expires' => time() - 3600,
									'path' => $parent,
									'domain' => $host,
									'secure' => is_ssl() ? true : false,
									'httpOnly' => true,
									'sameSite' => 'Strict'
								]);

								throw $exception; // Rethrow the exception
							}
						}
					}
				}
			/* `RequiredConstraintsViolated` can occur at this point if the token provided
				(i.e. the non-mediated token) was missing required claims, had invalid values,
				or has expired. Making a note of this here in case some specific processing is
				required later. In a similar vein, I'm also making an additional note for the
				`IdentityProviderException`.
			*/
			} catch (
				\League\OAuth2\Client\Provider\Exception\IdentityProviderException |
				\Lcobucci\JWT\Validation\RequiredConstraintsViolated |
				\Exception $exception) {
				// Update cached information
				$this->token = null;
				$this->scopes = null;
				$this->jwt = null;

/*

				$this->error->add(
					$exception->getCode() || 401,
					$exception->getMessage()
				);

				Log::Instance()->error($exception->getMessage(), [
					'section' => __METHOD__ . ' L:' . __LINE__,
					'error' => $this->error
				]);
*/				

                throw $exception; // Rethrow the exception
			}
			return($this->token);
		}

		protected function permitted(array $scopes): bool {
			$token = $this->token();
			if ($token instanceof Token\Plain) {
				$this->scopes = $this->scopes ?? preg_split('/\s+/', trim($token->claims()->get('scope', '')));

				$difference = array_diff($scopes, $this->scopes);

				// Are all requested scopes present?
				if (count($difference) < count($scopes)) {
					// At least some of the requested scopes are present
					return true;
				} else {
					return false;
				}
			}

			// Process Access Control
			return true;

			// Safest to default to false
			return false;
		}

		/*  Endpoint for deauthorization called as an explicit HTTP DELETE.
		*/
		public function deauthorize( \WP_REST_Request $request ): bool | \Exception {
			try
			{
				$authorization = $request->get_headers()['authorization'] ?? [];

				// Is there an Authorization Header?
				if (count($authorization) === 1) {
					// Trim whitespace.
					$jwt = trim($authorization[0]);

					// Remove 'Bearer ' prefix, if present.
					if (strpos( $jwt, 'Bearer ' ) === 0) {
						$jwt = substr($jwt, 7);
					}

					//	Check if the jwt is empty or not
					if ($jwt === "") {
						// Do something if JWT is empty?
					}
					else
					try {
						$this->parser = $this->parser ?? new Parser(new JoseEncoder());

						$token = $this->parser->parse($jwt);

						if ($token instanceof Token\Plain) {

							$sub = $token->claims()->get('sub');

							$home_url = home_url();

							$parsed_url = parse_url($home_url);

							$host = $parsed_url['host'];

							//	Resolve immediate path parent and structure so that cookies are resolved
							//  hierarchically.
							//
							$parent = $parsed_url['path'] . '/wp-json' . $this->authority . '/';

							// Clear cookies
							setcookie('_Bearer_' . $sub, "", [
								'expires' => time() - 3600,
								'path' => $parent,
								'domain' => $host,
								'secure' => is_ssl() ? true : false,
								'httpOnly' => true,
								'sameSite' => 'Strict'
							]);

							setcookie('_Bearer__' . $sub, "", [
								'expires' => time() - 3600,
								'path' => $parent,
								'domain' => $host,
								'secure' => is_ssl() ? true : false,
								'httpOnly' => true,
								'sameSite' => 'Strict'
							]);

							return(true);
						}
					}
					/* `RequiredConstraintsViolated` can occur at this point if the token provided
						(i.e. the non-mediated token) was missing required claims, had invalid values,
						or has expired. Making a note of this here in case some specific processing is
						required later. In a similar vein, I'm also making an additional note for the
						`IdentityProviderException`.
					*/
					catch (
						\League\OAuth2\Client\Provider\Exception\IdentityProviderException |
						\Lcobucci\JWT\Validation\RequiredConstraintsViolated |
						\Exception $exception) {

						throw $exception; // Rethrow the exception
					}
				}
			} catch (\Exception $exception) {
/*				
				$this->error->add(
					$exception->getCode() || 401,
					$exception->getMessage(), [
						'status' => 401
					]);

				Log::Instance()->error($exception->getMessage(), [
					'section' => __METHOD__ . ' L:' . __LINE__,
					'error' => $this->error
				]);
*/
				return($exception);
			}

			// Safest to default to Unauthorized
			return new \Exception('Unauthorized', 401);
		}

		/*  Endpoint for authorization called as an explicit HTTP GET or as a
			result of a redirect.
		*/
		public function authorize( \WP_REST_Request $request ): array | \Exception {
			$scope = $request->get_param('scope') ?? '';

			//  Are we processing authorization redirection?
			if ($request->get_param('redirectUri') ||
				$request->get_param('code')) {
				$home_url = home_url();

				$parsed_url = parse_url($home_url);

				$route = $request->get_route();

				$scheme = $parsed_url['scheme'];

				$host = $parsed_url['host'];

				$path = $parsed_url['path'] . '/wp-json' . $route;

				$redirect = $request->get_param('redirectUri') ?? $home_url;

				$provider = $this->provider();

				//
				if ($request->get_param('code') &&
					$request->get_param('state') ) {
					// Try to get an access token (using the authorization code grant)
					try {
						$redirect = base64_decode( $request->get_param('state') ) ?? $redirect;

						$result = $provider->getAccessToken('authorization_code', [
							'code' => $request->get_param('code')
						]);

						$this->jwt = $result->getToken() ?? '';

						$this->parser = $this->parser ?? new Parser(new JoseEncoder());

						$this->token = $this->token ?? $this->parser->parse($this->jwt);

						//	Resolve immediate path parent and structure so that cookies are resolved
						//  hierarchically.
						//
						$parent = $parsed_url['path'] . '/wp-json' . $this->authority . '/';

						//  Once the token has been obtained set the relevant cookies against the
						//  associated path. User the 'sub' claim as part of the cookie name to ensure
						//  verifiable uniqueness. Also prefix in a way that aligns with best practices:
						//  https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-20
						//
						setcookie('_Bearer_' . $this->token?->claims()->get('sub'),
							$this->_Bearer_ = $result?->getToken() ?? "", [
								'expires' => $result?->getExpires() ?? time() + 3600,
								'path' => $parent,
								'domain' => $host,
								'secure' => is_ssl() ? true : false,
								'httpOnly' => true,
								'sameSite' => 'Strict'
						]);
						setcookie('_Bearer__' . $this->token?->claims()->get('sub'),
							$this->_Bearer__ = $result?->getRefreshToken() ?? "", [
								'path' => $parent,
								'domain' => $host,
								'secure' => is_ssl() ? true : false,
								'httpOnly' => true,
								'sameSite' => 'Strict'
						]);
					} catch (\Exception $e) {
						$redirect = add_query_arg('error', $e->getMessage(), $redirect);
					}

					$parsed_url = parse_url( $redirect ) ;

					$scheme = $parsed_url['scheme'] ?? 'http';

					$path = $parsed_url['path'] ?? '/';

					// !!TODO!!: Check if the redirect URL is within the same domain

					//  Redirect to the spefied URL but only within the same domain
					$this->redirect( (isset($parsed_url['port']) ?
						$scheme . '://' . $host . ':' . $parsed_url['port'] . $path:
						$scheme . '://' . $host . $path) );
					exit;
				} else {
					//  Get the authorization URL to generate the state
					$authURL = $provider->getAuthorizationUrl([
						//  Request the scopes needed for the application; also request a refresh token
						'scope' => 'offline_access ' . $scope,
						//  Encode 'redirectUri' into state
						'state' => base64_encode($redirect)
					]);

					//  Get the authorization code
					wp_safe_redirect( $authURL );
					exit;
				}
			}
			else
			// Reaching this point means credential validation has already been performed
			if ($this->permitted(preg_split('/\s+/', trim($scope)))) {
				return $this->scopes;
			}
			else
			// Reaching this point means cached information has alredy been populated
			if (in_array('endpoint:mediate', $this->scopes, true)) {
				// Advise Mediation
				return new \Exception('Mediation Advised', 401);
			}

			// Safest to default to Unauthorized
			return new \Exception('Unauthorized',401);
		}

		abstract public static function namespace(): string;

		public function __construct(string $authority) {
			//  Structure the authority path so that it's API home relative
			$this->authority = '/' . static::namespace() . '/' . rtrim(ltrim($authority, '/'), '/');
		}
	}
}}

