require 'omniauth-oauth2'
require 'builder'

module OmniAuth
  module Strategies
    class Membermouse < OmniAuth::Strategies::OAuth2
      option :app_options, { app_event_id: nil }

      option :name, 'membermouse'

      option :client_options, { login_page_url: 'MUST BE PROVIDED' }

      uid { info[:uid] }

      info { raw_user_info }

      def request_phase
        redirect login_page_url
      end

      def callback_phase
        slug = request.params['slug']
        account = Account.find_by(slug: slug)
        app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')

        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + slug
        self.env['omniauth.redirect_url'] = request.params['redirect_url'].presence
        self.env['omniauth.app_event_id'] = app_event.id
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
