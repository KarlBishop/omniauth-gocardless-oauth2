require 'omniauth-oauth2'

module OmniAuth
	module Strategies
		class Gocardless < OmniAuth::Strategies::OAuth2

			option :name, "gocardless"

			option :client_options, {
				:site => "https://connect.gocardless.com",
		        :authorize_url => '/oauth/authorize',
		        :token_url => '/oauth/access_token'
			}

			uid { access_token.params['organisation_id'] }

      info do
        {
          email: access_token.params['email']
        }
      end

			# Required for omniauth-oauth2 >= 1.4
			# https://github.com/intridea/omniauth-oauth2/issues/81
			def callback_url
				full_host + script_name + callback_path
			end

			# Overridden method to fix missing credentials issue after update to OAuth2 2.0
			def build_access_token
				verifier = request.params['code']
				client.auth_code.get_token(verifier, {
					client_id: options.client_id,
					client_secret: options.client_secret,
					redirect_uri: callback_url,
				})
			end

		end
	end
end
