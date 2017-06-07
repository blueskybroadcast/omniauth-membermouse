require 'omniauth-oauth2'
require 'builder'

module OmniAuth
  module Strategies
    class Membermouse < OmniAuth::Strategies::OAuth2
      option :name, 'membermouse'

      option :client_options, { login_page_url: 'MUST BE PROVIDED' }

      uid { info[:uid] }

      info { raw_user_info }

      def request_phase
        redirect login_page_url
      end

      def callback_phase
        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + request.params['slug']
        self.env['omniauth.redirect_url'] = request.params['redirect_url'].presence
        call_app!
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid)
        hash.info = info
        hash
      end

      def raw_user_info
        {
          uid: request.params['uid'],
          first_name: request.params['first_name'],
          last_name: request.params['last_name'],
          email: request.params['email'],
          username: request.params['username'],
          is_member: request.params['is_member'],
          access_code: request.params['access_code']
        }
      end

      private

      def login_page_url
        options.client_options.login_page_url
      end
    end
  end
end
