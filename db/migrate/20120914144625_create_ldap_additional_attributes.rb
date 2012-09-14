class CreateLdapAdditionalAttributes < ActiveRecord::Migration
  
  def up
    create_table :ldap_additional_attributes do |t|
      t.references :principal, :null => false, :polymorphic => true
      t.string :attr_name, :null => false
      t.string :attr_value, :null => false
    end
  end

  def down
    drop_table :ldap_additional_attributes
  end
  
end
