class LdapAdditionalAttribute < ActiveRecord::Base
  
  belongs_to :principal, :polymorphic => true
  User.has_many :ldap_additional_attributes, :as => :principal
  Group.has_many :ldap_additional_attributes, :as => :principal
  
end
