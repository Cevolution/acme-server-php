<?php namespace cevolution\acme {
    use \Lcobucci\JWT\Token;
	use \Lcobucci\JWT\Token\Parser;
	use \Lcobucci\JWT\Encoding\JoseEncoder;
	use \Lcobucci\JWT\Signer\Rsa\Sha256 as RsSigner;
	use \Lcobucci\JWT\Validation\Validator as JWTValidator;
	use \Lcobucci\JWT\Validation\Constraint;
	use \Lcobucci\JWT\Signer\Key;

	use \Lcobucci\Clock\SystemClock;

	use \League\OAuth2\Client\Provider\AbstractProvider;	

	use \Psr\Http\Message\ServerRequestInterface;
	use \Psr\Http\Message\ResponseInterface;

	use \Nyholm\Psr7\Response;

if (!class_exists(__NAMESPACE__ . '\API')) {
	abstract class API {
		/** @var string Cookie name prefix for Mediated Access Tokens */
		private const AccessTokenPrefix = 'ACMETA';

		/** @var string Cookie name prefix for Mediated Refresh Tokens */
		private const RefreshTokenPrefix = 'ACMETR';

		//	Cached Bearer JWT
		private ?string $jwt = null;

		//	Cached JWT Parser
		private ?Parser $parser = null;

		//	Cached Mediated Access Token
		private ?string $mediatedAT = null;

		//	Cached Mediated Bearer Refresh Token
		private ?string $mediatedRT = null;

		//	Cached Decoded Bearer Token
		protected ?Token\Plain $token = null;

		//	Cached Decoded Scopes
		protected array $scope = [];

		protected bool $secure = true;

		protected string $host = "";

		//	Override to return the JWK for the supplied Key ID
		abstract protected function jwk(string $kid): string;

		//	Override to return the IssuedBy Constraint
		abstract protected function issuer(): Constraint\IssuedBy;

		//	Override to return the Provider instance initialized with the specified options
		abstract protected function provider(array $options = []): AbstractProvider;

		//	Override to return the Root relative path to the Authority
		abstract protected function authority(string $root = '/'): string;

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
					$kid = $token->headers()->get('kid', 0);

					$key = $this->jwk($kid) ?? "";

					$issuer = $this->issuer();

					// Token Validated?
					$validator = new JWTValidator();
					$validator->assert($token, $issuer);
					$validator->assert($token, new Constraint\SignedWith(new RsSigner(), Key\InMemory::plainText($key)));
					$validator->assert($token, new Constraint\LooseValidAt(
						SystemClock::fromUTC(),
						new \DateInterval('PT5S')	// 5 Second leeway
					));

					// Update cached token information
					$this->scope = preg_split('/\s+/', trim($token->claims()->get('scope', ''))) ?? [];
					$this->token = $token;
					$this->jwt = $jwt;

					// Enpoint mediated token checking?
					if (in_array('endpoint:mediate', $this->scope, true)) {
						// Get subject for mediated token checking
						$sub = $token->claims()->get('sub');

						// Does the user have a mediated Bearer Token in the Cookie?
						$_jwt = $this->mediatedAT ?? $_COOKIE[self::AccessTokenPrefix . $sub] ?? null;
						if ($_jwt && !empty($_jwt) && $_jwt !== $jwt)
						try {
							// Whilst the various cookie expiry and protection mechanisms should ensure
							// that the token is valid, we still validate the JWT to ensure that
							// the mediated token is valid (e.g. has not expired).
							$token = $this->parser->parse($_jwt);

							if ($token instanceof Token\Plain) {
								// Mediated Token must be signed from the same key set
								$kid = $token->headers()->get('kid', 0);

								$key = $this->jwk($kid) ?? "";

								// Token Validated?
								$validator->assert($token, $issuer);
								$validator->assert($token, new Constraint\SignedWith(new RsSigner(), Key\InMemory::plainText($key)));
								$validator->assert($token, new Constraint\LooseValidAt(SystemClock::fromUTC()));

								// Update cached token information
								$this->scope = preg_split('/\s+/', trim($token->claims()->get('scope', ''))) ?? [];
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
						$__jwt = $this->mediatedRT = $this->mediatedRT ?? $_COOKIE[self::RefreshTokenPrefix . $sub] ?? null;
						if ($__jwt && !empty($__jwt) && $_jwt !== $jwt) {
							//	Resolve immediate path to the authority as the parent, and structure so 
							//  that cookies are resolved hierarchically.
							//
							$authority = $this->authority();

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
								setcookie(self::AccessTokenPrefix . $sub,
									$this->mediatedAT = $result?->getToken() ?? "", [
										'expires' => $result?->getExpires() ?? time() + 3600,
										'path' => $authority,
										'domain' => $this->host,
										'secure' => $this->secure,
										'httpOnly' => true,
										'sameSite' => 'Strict'
								]);
								setcookie(self::RefreshTokenPrefix . $sub,
									$this->mediatedRT = $result?->getRefreshToken() ?? $this->mediatedRT ?? "", [
										'path' => $authority,
										'domain' => $this->host,
										'secure' => $this->secure,
										'httpOnly' => true,
										'sameSite' => 'Strict'
								]);

								// Update cached token information
								return($this->token($this->mediatedAT));
	//							$this->token = $this->parser->parse($this->__Bearer_ ?? '');
	//							$this->scopes = null;
	//							$this->jwt = $this->__Bearer_;
							}  catch (\Exception $exception) {
								// Clear cookies on error
								setcookie(self::AccessTokenPrefix . $sub, "", [
									'expires' => time() - 3600,
									'path' => $authority,
									'domain' => $this->host,
									'secure' => $this->secure,
									'httpOnly' => true,
									'sameSite' => 'Strict'
								]);

								setcookie(self::RefreshTokenPrefix . $sub, "", [
									'expires' => time() - 3600,
									'path' => $authority,
									'domain' => $this->host,
									'secure' => $this->secure,
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
				$this->scope = [];
				$this->token = null;
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

		protected function scope(array $scope): array {
			$token = $this->token ?? $this->token();

			if ($token instanceof Token\Plain) {
				$this->scope = $this->scope ?? preg_split('/\s+/', trim($token->claims()->get('scope', ''))) ?? [];

				$difference = array_diff($scope, $this->scope);

				// Are all requested scopes present?
				if (count($difference) < count($scope)) {
					// At least some of the requested scopes are present
					return $difference;
				} else {
					return [];
				}
			}

			// Safest to default to empty scope
			return [];
		}

		protected function jwt(ServerRequestInterface $request): string {
			$authHeader = $request->getHeaderLine('Authorization');

			if (preg_match('/^Bearer\s+(.+)$/i', $authHeader, $matches)) {
				return $matches[1];
			} else {
				return '';
			}				
		}
		
        /**
         * Authorization processing, typically called via an explicit HTTP request or as a result of a redirect.
         *
         * @param ServerRequestInterface $request
         * @return ResponseInterface
         */
		protected function authorization( ServerRequestInterface $request ): ResponseInterface {
			try {
				$parameters = $request->getQueryParams();

				$scope = $parameters['scope'] ?? '';

				//  Are we processing authorization redirection?
				if ($parameters['redirectUri'] ||
					$parameters['code']) {

					$uri = $request->getUri();		

	//				$home_url = home_url();

	//				$parsed_url = parse_url($home_url);

					$port = $uri->getPort();

					$route = $uri->getPath();

					$scheme = $uri->getScheme() ?? 'http';

					$this->secure = ($scheme === 'https');

					$this->host = $uri->getHost();

	//				$path = $parsed_url['path'] . '/wp-json' . $route;

					$redirect = $parameters['redirectUri'] ?? '/';

					$provider = $this->provider([
						'redirectUri' => $this->authority(($port) ?
							$scheme . '://' . $this->host . ':' . $port . $route:
							$scheme . '://' . $this->host . $route)
					]);

					//
					if ($parameters['code'] &&
						$parameters['state']) {
						// Try to get an access token (using the authorization code grant)
						try {
							$redirect = base64_decode( $parameters['state'] ) ?? $redirect;

							$result = $provider->getAccessToken('authorization_code', [
								'code' => $parameters['code']
							]);

							$this->jwt = $result->getToken() ?? '';

							$this->parser = $this->parser ?? new Parser(new JoseEncoder());

							$this->token = $this->token ?? $this->parser->parse($this->jwt);

							//	Resolve immediate path to the authority as the parent, and structure so 
							//  that cookies are resolved hierarchically.
							//
							$authority = $this->authority();

							//  Once the token has been obtained set the relevant cookies against the
							//  associated path. User the 'sub' claim as part of the cookie name to ensure
							//  verifiable uniqueness. Also prefix in a way that aligns with best practices:
							//  https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-20
							//
							setcookie(self::AccessTokenPrefix . $this->token?->claims()->get('sub'),
								$this->mediatedAT = $result?->getToken() ?? "", [
									'expires' => $result?->getExpires() ?? time() + 3600,
									'path' => $authority,
									'domain' => $this->host,
									'secure' => $this->secure,
									'httpOnly' => true,
									'sameSite' => 'Strict'
							]);
							setcookie(self::RefreshTokenPrefix . $this->token?->claims()->get('sub'),
								$this->mediatedRT = $result?->getRefreshToken() ?? "", [
									'path' => $authority,
									'domain' => $this->host,
									'secure' => $this->secure,
									'httpOnly' => true,
									'sameSite' => 'Strict'
							]);
						} catch (\Exception $e) {
	/*						
							return new Response(
								500,
								['Content-Type' => 'application/json'],
								json_encode([
									'code' => $e->getCode() || 500,
									'message' => $e->getMessage()
								])
							);
	*/						
						}

						$parsed_url = parse_url( $redirect ) ;

						$scheme = $parsed_url['scheme'] ?? 'http';

						$path = $parsed_url['path'] ?? '/';

						// !!TODO!!: Check if the redirect URL is within the same domain

						//  Redirect to the spefied URL but only within the same domain
						return new Response(
							302, [
								'Location' => (isset($parsed_url['port']) ?
									$scheme . '://' . $this->host . ':' . $parsed_url['port'] . $path:
									$scheme . '://' . $this->host . $path)
							]
						);
	/*
						$this->redirect( (isset($parsed_url['port']) ?
							$scheme . '://' . $host . ':' . $parsed_url['port'] . $path:
							$scheme . '://' . $host . $path) );
						exit;
	*/					
					} 
					else
					if (($this->token = $this->token( $this->jwt($request) )))
					{
						//	Calculate the authorization URL with generated state
						$authURL = $provider->getAuthorizationUrl([
							//  Request the scopes needed for the application; also request a refresh token
							'scope' => 'offline_access ' . $scope,
							//  Encode 'redirectUri' into state
							'state' => base64_encode($redirect)
						]);

						//  Redirect to authorize
						return new Response(
							302, ['Location' => $authURL]
						);
	/*					
						wp_safe_redirect( $authURL );
						exit;
	*/					
					}
				}
				else
				if (($this->token = $this->token( $this->jwt($request) )) === null) {
					
				}
				else
				// Reaching this point means credential validation has been performed, so validate token scopes
				if (count($this->scope = $this->scope(preg_split('/\s+/', trim($scope))) ?? [])) {
					return new Response(
						200,
						['Content-Type' => 'application/json'],
						json_encode($this->scope)
					);
				}
				else
				// Reaching this point may mean that mediation is required
				if (in_array('endpoint:mediate', $this->scope, true)) {
					// Advise Mediation
					return new Response(
						401,
						['Content-Type' => 'application/json'],
						json_encode([
							'code' => 'Mediation Advised',
							'message' => 'Access Control redirect recommended'
						])
					);
				}
			} catch (\Exception $e) {
			}

			// Safest to default to Unauthorized
			return new Response(
				401,
				['Content-Type' => 'application/json'],
				json_encode([
					'code' => 'Unauthorized',
					'message' => 'You are not allowed to perform this function'
				])
			);
		}

		/*  Deauthorization processing, typically called via an explicit HTTP DELETE.
		*/
		public function deauthorization( \WP_REST_Request $request ): bool | \Exception {
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
//							$parent = $parsed_url['path'] . '/wp-json' . $this->authority . '/';

							$parent = '';

							// Clear cookies
							setcookie(self::AccessTokenPrefix . $sub, "", [
								'expires' => time() - 3600,
								'path' => $parent,
								'domain' => $host,
								'secure' => $this->secure,
								'httpOnly' => true,
								'sameSite' => 'Strict'
							]);

							setcookie(self::RefreshTokenPrefix . $sub, "", [
								'expires' => time() - 3600,
								'path' => $parent,
								'domain' => $host,
								'secure' => $this->secure,
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

/*
		abstract public static function namespace(): string;

		public function __construct(string $authority) {
			//  Structure the authority path so that it's API home relative
			$this->authority = '/' . static::namespace() . '/' . rtrim(ltrim($authority, '/'), '/');
		}
*/			
	}
}}

