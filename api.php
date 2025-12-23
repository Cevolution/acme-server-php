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

if (!class_exists(__NAMESPACE__ . '\API')) {

	class APIException extends \RuntimeException {
	}

	class APIRedirectException extends APIException {
	}

	class APIUnauthorizedException extends APIException {
	}

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

		//	Cached Decoded Bearer Token Scopes
		protected array $scope = [];

		protected string $host = "";

		protected string $locus = "/";

		protected string $scheme = "https";

		//	Override to return the JWK for the supplied Key ID
		abstract protected function jwk(string $kid): string;

		//	Override to return the IssuedBy Constraint
		abstract protected function issuer(): Constraint\IssuedBy;

		//	Override to return the Provider instance initialized with the specified options
		abstract protected function provider(array $options = []): AbstractProvider;

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
							$secure = ($this->scheme === 'https');	

							try {
								$provider = $this->provider();

								// Refresh the mediated token using the Refresh Token
								$result = $provider->getAccessToken('refresh_token', [
									'refresh_token' => $__jwt
								]);

								//  Once the token has been obtained set the relevant cookies against the
								//  associated path, resolve based on the API locus as the parent (i.e.  
								//  structured so that cookies are resolved hierarchically). Use the 'sub' 
								// 	claim as part of the cookie name to ensure verifiable uniqueness. 
								// 	Also prefix in a way that aligns with best practices:
								//  https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-20
								//
								setcookie(self::AccessTokenPrefix . $sub,
									$this->mediatedAT = $result?->getToken() ?? "", [
										'expires' => $result?->getExpires() ?? time() + 3600,
										'path' => $this->locus,
										'domain' => $this->host,
										'secure' => $secure,
										'httpOnly' => true,
										'sameSite' => 'Strict'
								]);
								setcookie(self::RefreshTokenPrefix . $sub,
									$this->mediatedRT = $result?->getRefreshToken() ?? $this->mediatedRT ?? "", [
										'path' => $this->locus,
										'domain' => $this->host,
										'secure' => $secure,
										'httpOnly' => true,
										'sameSite' => 'Strict'
								]);

								// Update cached token information
								return($this->token($this->mediatedAT));
							}  catch (\Exception $exception) {
								// Clear cookies on error
								setcookie(self::AccessTokenPrefix . $sub, "", [
									'expires' => time() - 3600,
									'path' => $this->locus,
									'domain' => $this->host,
									'secure' => $secure,
									'httpOnly' => true,
									'sameSite' => 'Strict'
								]);

								setcookie(self::RefreshTokenPrefix . $sub, "", [
									'expires' => time() - 3600,
									'path' => $this->locus,
									'domain' => $this->host,
									'secure' => $secure,
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
/*
		protected function scope(array $scope): array {
			$token = $this->token();

			if ($token instanceof Token\Plain) {
				$this->scope = preg_split('/\s+/', trim($token->claims()->get('scope', ''))) ?? [];

				return array_intersect($scope, $this->scope);

				// Are all requested scopes present?
				if ($intersection === []) {
					// All requested scopes are present
					return $scope;
				}
				else
				if (count($intersection) < count($scope)) {
					// At least some of the requested scopes are present
					return $intersection;
				} 
			}

			// Safest to default to empty scope
			return [];
		}
*/
		protected function jwt(string $header): string {
			if (preg_match('/^Bearer\s+(.+)$/i', $header, $matches)) {
				return $matches[1];
			} else {
				return '';
			}				
		}
		
        /**
         * Authorization processing, typically called via an explicit HTTP request or as a result of a redirect.
         *
		 * @param string $token The Bearer token (typically a JWT).
		 * @param string $authority The Authority endpoint (URL without parameters).
		 * @param array $parameters (URL) Parameters for authorization processing.
		 * @return array The authorized scopes.
		 * @throws \Exception
         */
		protected function authorization( 
			string $token,
			string $authority,
			array $parameters = []): array {

			$components = parse_url($authority);

			$host = $this->host = $components['host'];

			$locus = $this->locus = preg_replace('#/[^/]+$#', '', rtrim($components['path'] ?? '/', '/')) . '/';			

			$scheme = $this->scheme = $components['scheme'];

			$redirect = $parameters['redirectUri'] ?? null;

			$scope = $parameters['scope'] ?? '';

			$code = $parameters['code'] ?? null;

			//  Are we processing authorization redirection?
			if ($redirect || $code) {
				$redirect = $redirect ?? '/';

				$state = $parameters['state'] ?? '';

				$provider = $this->provider([
					'redirectUri' => $authority
				]);

				//
				if ($code && $state) {
					// Try to get an access token (using the authorization code grant)
					try {
						$secure = ($scheme === 'https');	

						$redirect = base64_decode( $state ) ?? $redirect;

						$result = $provider->getAccessToken('authorization_code', [
							'code' => $parameters['code']
						]);

						$this->jwt = $result->getToken() ?? '';

						$this->parser = $this->parser ?? new Parser(new JoseEncoder());

						$this->token = $this->parser->parse($this->jwt);

						//  Once the token has been obtained set the relevant cookies against the
						//  associated path, resolve based on the API locus as the parent (i.e.  
						//  structured so that cookies are resolved hierarchically). Use the 'sub' 
						// 	claim as part of the cookie name to ensure verifiable uniqueness. 
						// 	Also prefix in a way that aligns with best practices:
						//  https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-20
						//
						setcookie(self::AccessTokenPrefix . $this->token?->claims()->get('sub'),
							$this->mediatedAT = $result?->getToken() ?? "", [
								'expires' => $result?->getExpires() ?? time() + 3600,
								'path' => $locus,
								'domain' => $host,
								'secure' => $secure,
								'httpOnly' => true,
								'sameSite' => 'Strict'
						]);						
						setcookie(self::RefreshTokenPrefix . $this->token?->claims()->get('sub'),
							$this->mediatedRT = $result?->getRefreshToken() ?? "", [
								'path' => $locus,
								'domain' => $host,
								'secure' => $secure,
								'httpOnly' => true,
								'sameSite' => 'Strict'
						]);
					} catch (\Exception $exception) {
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
/*
					$components = parse_url( $redirect ) ;

					$scheme = $components['scheme'] ?? 'http';

					$path = $components['path'] ?? '/';

					$port = $components['port'] ?? null;

					//  Redirect to the spefied URL but only within the same domain
					throw new APIRedirectException(
						isset($port) ?
							$scheme . '://' . $this->host . ':' . $port . $path:
							$scheme . '://' . $this->host . $path,
						302);
*/
					throw new APIRedirectException($redirect, 302);							
				} else {
					//	Calculate the authorization URL with generated state
					$authURL = $provider->getAuthorizationUrl([
						//  Request the scopes needed for the application; also request a refresh token
						'scope' => 'offline_access ' . $scope,
						//  Encode 'redirectUri' into state
						'state' => base64_encode($redirect)
					]);

					//  Redirect to authorize
					throw new APIRedirectException($authURL, 302);
				}
			}
			else
			if (($this->token = $this->token( $token ))) {

				$this->scope = preg_split('/\s+/', trim($this->token->claims()->get('scope', ''))) ?? [];

				$intersection = array_intersect(preg_split('/\s+/', trim($scope)) ?? [], $this->scope);

				// Reaching this point validate token scopes
				if (count($intersection)) {
					return $intersection;
				}
				else
				// Reaching this point may mean that mediation is required
				if (in_array('endpoint:mediate', 
						preg_split('/\s+/', 
							trim($this->token->claims()->get('scope', ''))) ?? [], 
						true)) 
				{
					// Advise Mediation
					throw new APIUnauthorizedException('Mediation Advised' , 401);
				}
/*


				// Reaching this point validate token scopes
				if (count($this->scope = $this->scope(preg_split('/\s+/', trim($scope))) ?? [])) {
					return new Response(
						200,
						['Content-Type' => 'application/json'],
						json_encode($this->scope)
					);
				}
				else
				// Reaching this point may mean that mediation is required
				if ($this->token instanceof Token\Plain && in_array('endpoint:mediate', 
						preg_split('/\s+/', 
							trim($this->token->claims()->get('scope', ''))) ?? [], 
						true)) 
				{
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
*/
			}

			// Safest to default to Unauthorized
			throw new APIUnauthorizedException('Unauthorized' , 401);
		}

		/**
		 * Deauthorization processing, typically called via an explicit HTTP DELETE.
		 *
		 * @param string $token The Bearer token (typically a JWT).
		 * @param string $authority The Authority endpoint (URL without parameters).
		 * @return bool Result of deauthorization.
		 * @throws \Exception
		*/
		public function deauthorization(
			string $token,
			string $authority): bool {
			$components = parse_url($authority);

			$host = $this->host = $components['host'];

			$locus = $this->locus = preg_replace('#/[^/]+$#', '', rtrim($components['path'] ?? '/', '/')) . '/';
			
			$scheme = $this->scheme = $components['scheme'];

			try
			{
				$this->parser = $this->parser ?? new Parser(new JoseEncoder());

				$this->token = $this->parser->parse($token);

				if ($this->token instanceof Token\Plain) {

					$sub = $this->token->claims()->get('sub');

					$secure = ($scheme === 'https');	

					// Clear cookies
					setcookie(self::AccessTokenPrefix . $sub, "", [
						'expires' => time() - 3600,
						'path' => $locus,
						'domain' => $host,
						'secure' => $secure,
						'httpOnly' => true,
						'sameSite' => 'Strict'
					]);

					setcookie(self::RefreshTokenPrefix . $sub, "", [
						'expires' => time() - 3600,
						'path' => $locus,
						'domain' => $host,
						'secure' => $secure,
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

			// Safest to default to false
			return false;
		}

/*
		abstract public static function namespace(): string;
*/			
/*
		protected function __construct(
			string $host,
			string $scheme = 'https') {
			$this->secure = ($scheme === 'https');
			$this->host = $host;
		}
*/			
	}
}}

