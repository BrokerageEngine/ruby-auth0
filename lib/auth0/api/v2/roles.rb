module Auth0
  module Api
    module V2
      # Methods to use the roles endpoints
      module Roles
        attr_reader :roles_path

        # Retrieves a list of Auth0 roles.
        # @see https://auth0.com/docs/api/management/v2#!/Roles/get_roles
        # @param options [hash] The Hash options used to refine the Role results.
        #   * :per_page [integer] The amount of entries per page. Default: 50. Max value: 100.
        #   * :page [integer] The page number. Zero based.
        #   * :include_totals [boolean] True if a query summary must be included in the result.
        #   * :sort [string] The field to use for sorting. 1 == ascending and -1 == descending.
        #   * :connection [string] Connection to filter results by.
        #   * :fields [string] A comma separated list of result fields.
        #   * :include_fields [boolean] True to include :fields, false to exclude.
        #   * :name_filter [string]  An optional case-insensitive filter to apply to search for roles by name
        # @return [json] Returns the list of existing roles.
        def roles(options = {})
          request_params = {
              per_page: options.fetch(:per_page, nil),
              page: options.fetch(:page, nil),
              include_totals: options.fetch(:include_totals, nil),
              name_filter: options.fetch(:name_filter, nil)
          }
          get(roles_path, request_params)
        end

        alias get_roles roles

        # Creates a new role according to optional parameters received.
        # The attribute connection is always mandatory but depending on the type of connection you are using there
        # could be others too. For instance, Auth0 DB Connections require email and password.
        # @see https://auth0.com/docs/api/v2#!/Roles/post_roles
        # @param name [string] The role name.
        # @param options [hash]
        #   * :connection [string] The connection the role belongs to.
        # @return [json] Returns the created role.
        def create_role(name, options = {})
          request_params = Hash[options.map {|(k, v)| [k.to_sym, v]}]
          request_params[:name] = name
          post(roles_path, request_params)
        end

        # Delete all roles - USE WITH CAUTION
        # @see https://auth0.com/docs/api/v2#!/Roles/delete_roles
        def delete_roles
          delete(roles_path)
        end

        # Retrieves a role given a role_id
        # @see https://auth0.com/docs/api/v2#!/Roles/get_roles_by_id
        # @param role_id [string] The role_id of the role to retrieve.
        # @param fields [string] A comma separated list of fields to include or exclude from the result.
        # @param include_fields [boolean] True if the fields specified are to be included in the result, false otherwise.
        #
        # @return [json] Returns the role with the given role_id if it exists.
        def role(role_id, fields: nil, include_fields: true)
          raise Auth0::MissingRoleId, 'Must supply a valid role_id' if role_id.to_s.empty?
          path = "#{roles_path}/#{role_id}"
          request_params = {
              fields: fields,
              include_fields: include_fields
          }
          get(path, request_params)
        end

        # Deletes a single role given its id
        # @see https://auth0.com/docs/api/v2#!/Roles/delete_roles_by_id
        # @param role_id [string] The role_id of the role to delete.
        def delete_role(role_id)
          raise Auth0::MissingRoleId, 'Must supply a valid role_id' if role_id.to_s.empty?
          path = "#{roles_path}/#{role_id}"
          delete(path)
        end

        # Updates a role with the object's properties received in the optional parameters.
        # These are the attributes that can be updated at the root level:
        # blocked, email_verified, email, verify_email, password, phone_number, phone_verified,
        # verify_password, role_metadata, app_metadata, rolename
        # Some considerations:
        # The properties of the new object will replace the old ones.
        # The metadata fields are an exception to this rule (role_metadata and app_metadata). These properties are
        # merged instead of being replaced but be careful, the merge only occurs on the first level.
        # If you are updating email_verified, phone_verified, rolename or password you need to specify the connection
        # property too.
        # If your are updating email or phone_number you need to specify the connection and the client_id properties.
        # @see https://auth0.com/docs/api/v2#!/Roles/patch_roles_by_id
        # @param role_id [string] The role_id of the role to update.
        # @param body [hash] The optional parametes to update.
        #
        # @return [json] Returns the updated role.
        def patch_role(role_id, body)
          raise Auth0::MissingRoleId, 'Must supply a valid role_id' if role_id.to_s.empty?
          raise Auth0::InvalidParameter, 'Must supply a valid body' if body.to_s.empty? || body.empty?
          path = "#{roles_path}/#{role_id}"
          patch(path, body)
        end

        alias update_role patch_role


        # disconnect permissions
        # associate permission
        # get role user
        # assign user to role

        def role_permissions(role_id, options = {})
          request_params = {
              per_page: options.fetch(:per_page, nil),
              page: options.fetch(:page, nil),
              include_totals: options.fetch(:include_totals, nil),
              name_filter: options.fetch(:name_filter, nil)
          }
          path = "#{roles_path}/#{role_id}/permissions"
          get(path, request_params)

        end

        def role_users(role_id, options = {})
          request_params = {
              per_page: options.fetch(:per_page, nil),
              page: options.fetch(:page, nil),
              include_totals: options.fetch(:include_totals, nil),
              name_filter: options.fetch(:name_filter, nil)
          }
          path = "#{roles_path}/#{role_id}/users"
          get(path, request_params)

        end

        #
        # # Delete a role's multifactor provider
        # # @see https://auth0.com/docs/api/v2#!/Roles/delete_multifactor_by_provider
        # # @param role_id [string] The role_id of the role to delete the multifactor provider from.
        # # @param provider_name [string] The multifactor provider. Supported values 'duo' or 'google-authenticator'.
        # def delete_role_provider(role_id, provider_name)
        #   raise Auth0::MissingRoleId, 'Must supply a valid role_id' if role_id.to_s.empty?
        #   raise Auth0::InvalidParameter, 'Must supply a valid provider name' if provider_name.to_s.empty?
        #   path = "#{roles_path}/#{role_id}/multifactor/#{provider_name}"
        #   delete(path)
        # end
        #
        # # Links the account specified in the body (secondary account) to the account specified by the id param
        # # of the URL (primary account).
        # # 1. With the authenticated primary account's JWT in the Authorization header, which has the
        # # update:current_role_identities scope. In this case only the link_with param is required in the body,
        # # containing the JWT obtained upon the secondary account's authentication.
        # # 2. With an API V2 generated token with update:roles scope. In this case you need to send provider and role_id
        # # in the body. Optionally you can also send the connection_id param which is suitable for identifying a
        # # particular database connection for the 'auth0' provider.
        # # @see https://auth0.com/docs/api/v2#!/Roles/post_identities
        # # @param role_id [string] The role_id of the primary identity where you are linking the secondary account to.
        # # @param body [string] the options to link the account to.
        # #
        # # @return [json] Returns the new array of the primary account identities.
        # def link_role_account(role_id, body)
        #   raise Auth0::MissingRoleId, 'Must supply a valid role_id' if role_id.to_s.empty?
        #   raise Auth0::InvalidParameter, 'Must supply a valid body' if body.to_s.empty?
        #   path = "#{roles_path}/#{role_id}/identities"
        #   post(path, body)
        # end
        #
        # # Unlink a role account
        # # @see https://auth0.com/docs/api/v2#!/Roles/delete_provider_by_role_id
        # # @param role_id [string] The role_id of the role identity.
        # # @param provider [string] The type of identity provider.
        # # @param secondary_role_id [string] The unique identifier for the role for the identity.
        # #
        # # @return [json] Returns the array of the unlinked account identities.
        # def unlink_roles_account(role_id, provider, secondary_role_id)
        #   raise Auth0::MissingRoleId, 'Must supply a valid role_id' if role_id.to_s.empty?
        #   raise Auth0::MissingRoleId, 'Must supply a valid secondary role_id' if secondary_role_id.to_s.empty?
        #   raise Auth0::InvalidParameter, 'Must supply a valid provider' if provider.to_s.empty?
        #   path = "#{roles_path}/#{role_id}/identities/#{provider}/#{secondary_role_id}"
        #   delete(path)
        # end
        #
        # # Retrieve every log event for a specific role id
        # # @see https://auth0.com/docs/api/management/v2#!/Roles/get_logs_by_role
        # # @param role_id [string] The role_id of the logs to retrieve.
        # # @param options [hash]
        # #   * :per_page [integer] The amount of entries per page. Default: 50. Max value: 100.
        # #   * :page [integer]  The page number. Zero based.
        # #   * :include_totals [boolean] True if a query summary must be included in the result.
        # #   * :sort [string] The field to use for sorting. 1 == ascending and -1 == descending.
        # #
        # # @return [json] Returns the list of existing log entries for the given role_id.
        # # rubocop:disable Metrics/MethodLength, Metrics/AbcSize
        # def role_logs(role_id, options = {})
        #   raise Auth0::MissingRoleId, 'Must supply a valid role_id' if role_id.to_s.empty?
        #   path = "#{roles_path}/#{role_id}/logs"
        #   request_params = {
        #     role_id:        role_id,
        #     per_page:       options.fetch(:per_page, nil),
        #     page:           options.fetch(:page, nil),
        #     include_totals: options.fetch(:include_totals, nil),
        #     sort:           options.fetch(:sort, nil)
        #   }
        #   if request_params[:per_page].to_i > 100
        #     raise Auth0::InvalidParameter, 'The total amount of entries per page should be less than 100'
        #   end
        #   sort_pattern = /^(([a-zA-Z0-9_\.]+))\:(1|-1)$/
        #   if !request_params[:sort].nil? && !sort_pattern.match(request_params[:sort])
        #     raise Auth0::InvalidParameter, 'Sort does not match pattern ^(([a-zA-Z0-9_\\.]+))\\:(1|-1)$'
        #   end
        #   get(path, request_params)
        # end
        # alias get_role_log_events role_logs
        #

        private

        # Roles API path
        def roles_path
          @roles_path ||= '/api/v2/roles'
        end
      end
    end
  end
end
