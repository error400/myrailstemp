if yes?("Do you want Authorization? (yes on no)")
plugin 'restful_authentication', :git => 'git://github.com/technoweenie/restful-authentication.git'

puts "-"
puts "Plugin restful_authentication installed"
puts "-"

if yes?("Do you want to have Activationmails? (yes or no)")
  #run "./script/generate authenticated user sessions --include-activation"
generate(:authenticated,'user','sessions','--include-activation')
  route "map.activate '/activate/:activation_code', :controller => 'users', :action => 'activate', :activation_code => nil"
else  
  #run "./script/generate authenticated user sessions"
  generate(:authenticated,'user','sessions')
end

# route "map.signup '/signup', :controller => 'users', :action => 'new'"
# route "map.login '/login', :controller => 'session', :action => 'new'"
# route "map.logout '/logout', :controller => 'session', :action => 'destroy'"

file 'app/controllers/application_controller.rb',
%q{class ApplicationController < ActionController::Base
  include AuthenticatedSystem
  helper :all
  protect_from_forgery # See ActionController::RequestForgeryProtection for details
  # Scrub sensitive parameters from your log
  # filter_parameter_logging :password
end
}

puts ""
puts "Authentication enabled (user, sessions)"
puts ""

end

if yes? ("Do you want Roles? (yes or no)")
plugin "declarative_authorization", :git => "git://github.com/stffn/declarative_authorization.git"

# ======================
# = set up controllers =
# ======================

file 'app/controllers/application_controller.rb',
%q{# Filters added to this controller apply to all controllers in the application.
# Likewise, all the methods added will be available for all controllers.

class ApplicationController < ActionController::Base
  helper :all # include all helpers, all the time
  helper_method :current_user, :logged_in?

  # See ActionController::RequestForgeryProtection for details
  # Uncomment the :secret if you're not using the cookie session store
  protect_from_forgery # :secret => '8e49e1c945c636c4e5062b7fa72f2333'
  
  # See ActionController::Base for details 
  # Uncomment this to filter the contents of submitted sensitive data parameters
  # from your application log (in this case, all fields with names like "password"). 
  # filter_parameter_logging :password

  include AuthenticatedSystem
  
  # Start of declaration_authorization-related code
  before_filter :set_current_user
  
  # One way of using declarative_authorization is to restrict access
  # to controller actions by default by stating the following line.
  # This installs a default before_filter for authorization according
  # to the action names.
  #filter_access_to :all
  
  protected
  # There are multiple ways of handling authorization failures.  
  # One is to implement a permission denied method as shown below.  
  # If none is defined, either a simple string is displayed
  # to the user ("You are not allowed...", default) or the authorization
  # exception is raised.  TODO state configuration option
  # 
  def permission_denied
   respond_to do |format|
       flash[:error] = 'Sorry, you are not allowed to view the requested page.'
       format.html { redirect_to(:back) rescue redirect_to('/') }
       format.xml  { head :unauthorized }
       format.js   { head :unauthorized }
     end
  end
  
  # set_current_user sets the global current user for this request.  This
  # is used by model security that does not have access to the
  # controller#current_user method.  It is called as a before_filter.
  def set_current_user
    Authorization.current_user = current_user
  end
end  
}

file 'app/controllers/sessions_controller.rb',
%q{# This controller handles the login/logout function of the site.  
class SessionsController < ApplicationController
  # This controller has no filter_access_to statements, as everyone
  # may try to login or logout.

  # render new.rhtml
  def new
  end

  def create
    logout_keeping_session!
    user = User.authenticate(params[:login], params[:password])
    user = User.find_by_login(params[:login]) if params[:force] and not user
    if user
      # Protects against session fixation attacks, causes request forgery
      # protection if user resubmits an earlier form using back
      # button. Uncomment if you understand the tradeoffs.
      # reset_session
      self.current_user = user
      #new_cookie_flag = (params[:remember_me] == "1")
      #handle_remember_cookie! new_cookie_flag
      redirect_back_or_default('/')
      flash[:notice] = "Logged in successfully"
    else
      note_failed_signin
      @login       = params[:login]
      @remember_me = params[:remember_me]
      render :action => 'new'
    end
  end

  def destroy
    logout_killing_session!
    flash[:notice] = "You have been logged out."
    redirect_back_or_default('/')
  end

protected
  # Track failed login attempts
  def note_failed_signin
    flash[:error] = "Couldn't log you in as '#{params[:login]}'"
    logger.warn "Failed login for '#{params[:login]}' from #{request.remote_ip} at #{Time.now.utc}"
  end
end
}

file 'app/controllers/users_controller.rb',
%q{class UsersController < ApplicationController
  # See ConferenceController for comments on the most common use of 
  # filter_access_to
  filter_access_to :all
  filter_access_to :edit, :update, :attribute_check => true

  # render new.rhtml
  def new
    @user = User.new
  end
 
  def create
    logout_keeping_session!
    @user = User.new(params[:user])
    success = @user && @user.save
    if success && @user.errors.empty?
            # Protects against session fixation attacks, causes request forgery
      # protection if visitor resubmits an earlier form using back
      # button. Uncomment if you understand the tradeoffs.
      # reset session
      self.current_user = @user # !! now logged in
            redirect_back_or_default('/')
      flash[:notice] = "Thanks for signing up!"
    else
      flash[:error]  = "We couldn't set up that account, sorry.  Please try again, or contact an admin."
      render :action => 'new'
    end
  end
  
  def index
    @users = User.find(:all)

    respond_to do |format|
      format.html # index.html.erb
      format.xml  { render :xml => @users }
    end
  end
  
  def edit
    @user = User.find(params[:id])
  end
  
  def update
    @user = User.find(params[:id])

    respond_to do |format|
      if @user.update_attributes(params[:user])
        flash[:notice] = 'User was successfully updated.'
        format.html { redirect_to(User.new) }
        format.xml  { head :ok }
      else
        format.html { render :action => "edit" }
        format.xml  { render :xml => @user.errors, :status => :unprocessable_entity }
      end
    end
  end
  
end  
}

# ==================
# = set up helpers =
# ==================

file 'app/helpers/users_helper.rb',
%q{module UsersHelper
  
  #
  # Use this to wrap view elements that the user can't access.
  # !! Note: this is an *interface*, not *security* feature !!
  # You need to do all access control at the controller level.
  #
  # Example:
  # <%= if_authorized?(:index,   User)  do link_to('List all users', users_path) end %> |
  # <%= if_authorized?(:edit,    @user) do link_to('Edit this user', edit_user_path) end %> |
  # <%= if_authorized?(:destroy, @user) do link_to 'Destroy', @user, :confirm => 'Are you sure?', :method => :delete end %> 
  #
  #
  def if_authorized?(action, resource, &block)
    if authorized?(action, resource)
      yield action, resource
    end
  end

  #
  # Link to user's page ('users/1')
  #
  # By default, their login is used as link text and link title (tooltip)
  #
  # Takes options
  # * :content_text => 'Content text in place of user.login', escaped with
  #   the standard h() function.
  # * :content_method => :user_instance_method_to_call_for_content_text
  # * :title_method => :user_instance_method_to_call_for_title_attribute
  # * as well as link_to()'s standard options
  #
  # Examples:
  #   link_to_user @user
  #   # => <a href="/users/3" title="barmy">barmy</a>
  #
  #   # if you've added a .name attribute:
  #  content_tag :span, :class => :vcard do
  #    (link_to_user user, :class => 'fn n', :title_method => :login, :content_method => :name) +
  #          ': ' + (content_tag :span, user.email, :class => 'email')
  #   end
  #   # => <span class="vcard"><a href="/users/3" title="barmy" class="fn n">Cyril Fotheringay-Phipps</a>: <span class="email">barmy@blandings.com</span></span>
  #
  #   link_to_user @user, :content_text => 'Your user page'
  #   # => <a href="/users/3" title="barmy" class="nickname">Your user page</a>
  #
  def link_to_user(user, options={})
    raise "Invalid user" unless user
    options.reverse_merge! :content_method => :login, :title_method => :login, :class => :nickname
    content_text      = options.delete(:content_text)
    content_text    ||= user.send(options.delete(:content_method))
    options[:title] ||= user.send(options.delete(:title_method))
    link_to h(content_text), user_path(user), options
  end

  #
  # Link to login page using remote ip address as link content
  #
  # The :title (and thus, tooltip) is set to the IP address 
  #
  # Examples:
  #   link_to_login_with_IP
  #   # => <a href="/login" title="169.69.69.69">169.69.69.69</a>
  #
  #   link_to_login_with_IP :content_text => 'not signed in'
  #   # => <a href="/login" title="169.69.69.69">not signed in</a>
  #
  def link_to_login_with_IP content_text=nil, options={}
    ip_addr           = request.remote_ip
    content_text    ||= ip_addr
    options.reverse_merge! :title => ip_addr
    if tag = options.delete(:tag)
      content_tag tag, h(content_text), options
    else
      link_to h(content_text), login_path, options
    end
  end

  #
  # Link to the current user's page (using link_to_user) or to the login page
  # (using link_to_login_with_IP).
  #
  def link_to_current_user(options={})
    if current_user
      link_to_user current_user, options
    else
      content_text = options.delete(:content_text) || 'not signed in'
      # kill ignored options from link_to_user
      [:content_method, :title_method].each{|opt| options.delete(opt)} 
      link_to_login_with_IP content_text, options
    end
  end

end  
}

# =================
# = set up models =
# =================

file 'app/models/user.rb',
%q{require 'digest/sha1'

class User < ActiveRecord::Base
  using_access_control
  
  include Authentication
  include Authentication::ByPassword
  #include Authentication::ByCookieToken

  validates_presence_of     :login
  validates_length_of       :login,    :within => 3..40
  validates_uniqueness_of   :login
  validates_format_of       :login,    :with => Authentication.login_regex, :message => Authentication.bad_login_message

  validates_format_of       :name,     :with => Authentication.name_regex,  :message => Authentication.bad_name_message, :allow_nil => true
  validates_length_of       :name,     :maximum => 100

  validates_presence_of     :email
  validates_length_of       :email,    :within => 6..100 #r@a.wk
  validates_uniqueness_of   :email
  validates_format_of       :email,    :with => Authentication.email_regex, :message => Authentication.bad_email_message

  

  # HACK HACK HACK -- how to do attr_accessible from here?
  # prevents a user from submitting a crafted form that bypasses activation
  # anything else you want your user to change should be added here.
  attr_accessible :login, :email, :name, :password, :password_confirmation, :roles

  # Authenticates a user by their login name and unencrypted password.  Returns the user or nil.
  #
  # uff.  this is really an authorization, not authentication routine.  
  # We really need a Dispatch Chain here or something.
  # This will also let us return a human error message.
  #
  def self.authenticate(login, password)
    u = find_by_login(login) # need to get the salt
    u && u.authenticated?(password) ? u : nil
  end

  
  # Start of code needed for the declarative_authorization plugin
  # 
  # Roles are stored in a serialized field of the User model.
  # For many applications a separate UserRole model might be a
  # better choice.
  serialize :roles, Array

  # The necessary method for the plugin to find out about the role symbols
  # Roles returns e.g. [:admin]
  def role_symbols
    r = (roles || []).map {|r| r.to_sym}
  end
  # End of declarative_authorization code
end
}

# ================
# = create views =
# ================

file 'app/views/users/_user_bar.html.erb',
%q{<% if logged_in? -%>
  <div id="user-bar-greeting">Logged in as <%= link_to_current_user :content_method => :login %></div>
  <div id="user-bar-action"  >(<%= link_to "Log out", logout_path, { :title => "Log out" }    %>)</div>
<% else -%>
  <div id="user-bar-greeting"><%= abbr_tag_with_IP 'Not logged in', :style => 'border: none;' %></div>
  <div id="user-bar-action"  ><%= link_to "Log in",  login_path,  { :title => "Log in" } %> /
                               <%= link_to "Sign up", signup_path, { :title => "Create an account" } %></div>
<% end -%>
}

file 'app/views/users/edit.html.erb',
%q{<h1>Editing user: <%= h @user.login%></h1>

<% form_for(@user) do |f| %>
  <%= f.error_messages %>

  <p>
    <%= f.label :login %><br />
    <%= f.text_field :login %>
  </p>
  <p>
    <%= f.label :roles %><br />
    <%= f.select :roles, (controller.authorization_engine.roles + (@user.roles || [])).uniq, {}, {:multiple => true} %>
  </p>
  <p>
    <%= f.submit "Update" %>
  </p>
<% end %>

<%= link_to 'Back', users_path %>  
}

file 'app/views/users/edit.html.erb',
%q{<h1>Editing user: <%= h @user.login%></h1>

<% form_for(@user) do |f| %>
  <%= f.error_messages %>

  <p>
    <%= f.label :login %><br />
    <%= f.text_field :login %>
  </p>
  <p>
    <%= f.label :roles %><br />
    <%= f.select :roles, (controller.authorization_engine.roles + (@user.roles || [])).uniq, {}, {:multiple => true} %>
  </p>
  <p>
    <%= f.submit "Update" %>
  </p>
<% end %>

<%= link_to 'Back', users_path %>
}

file 'app/views/users/index.html.erb',
%q{<h1>Users</h1>

  <table>
    <tr>
      <th>Login</th>
      <th>Roles</th>
    </tr>
  <% for user in @users %>
    <tr>
      <td><b><%= h user.login %></b></td>
      <td><%= h user.roles.map(&:to_s) * ',' if user.roles %></td>
      <td>
        <%= link_to 'Edit', edit_user_path(user) if permitted_to? :edit, user %>
        <%= link_to 'Destroy', user, :confirm => 'Are you sure?', :method => :delete if permitted_to? :delete, user %>
      </td>
    </tr>
  <% end %>
  </table>
}

# ================================
# = set up AuthRules in "config" =
# ================================

file 'config/authorization_rules.rb',
%q{authorization do
  role :guest do
    has_permission_on :orders, :to => :read do
      if_attribute :published => true
    end
    has_permission_on :infos, :to => :read do
      if_permitted_to :read, :order
    end
    has_permission_on :users, :to => :create
    has_permission_on :authorization_rules, :to => :read
    has_permission_on :authorization_usages, :to => :read
  end
  
  role :user do
    includes :guest
    # has_permission_on :order_attendees, :to => :create do
    #       if_attribute :user => is {user}, 
    #         :order => { :published => true }
    #     end
    #     has_permission_on :order_attendees, :to => :delete do
    #       if_attribute :user => is {user}, 
    #         :order => { :attendees => contains {user} }
    #     end
    # has_permission_on :info_attendees, :to => :create do
    #       if_attribute :info => { :order => { :attendees => contains {user} }}
    #     end
    #     has_permission_on :info_attendees, :to => :delete do
    #       if_attribute :user => is {user}
    #     end
  end
  
  role :admin do
    #has_permission_on [:orders, :users, :infos], :to => :manage
    has_permission_on :users, :to => :manage
    has_permission_on :authorization_rules, :to => :read
    has_permission_on :authorization_usages, :to => :read
  end
end

privileges do
  privilege :manage, :includes => [:create, :read, :update, :delete]
  privilege :read, :includes => [:index, :show]
  privilege :create, :includes => :new
  privilege :update, :includes => :edit
  privilege :delete, :includes => :destroy
end
}

# =====================
# = set up migrations =
# =====================

generate(:migration,'AddRolesToUsers','roles:text')

# ================================
# = add migration for first user =
# ================================

file 'db/migrate/99999999999999_addfirstuser.rb',
%q{require "vendor/plugins/declarative_authorization/lib/declarative_authorization/maintenance"

class AddAdminUser < ActiveRecord::Migration
  def self.up
    Authorization::Maintenance::without_access_control do
      u = User.create(:login => 'admin', :email => 'foo@bar.com',
        :password => 'admin', :password_confirmation => 'admin')
      p u
      u.save!
    end
  end

  def self.down
    Authorization::Maintenance::without_access_control do
      u = User.find_by_login("admin")
      u.destroy if u
    end
  end
end  
}

end
