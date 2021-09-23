# -*- indent-tabs-mode: t; tab-width: 4; -*-
#	
# User management tests

_test_mixed_case() {
	# helper function sends multiple email messages to test mixed case
	# input scenarios
	local alices=($1)  # list of mixed-case email addresses for alice
	local bobs=($2)    # list of mixed-case email addresses for bob
	local aliases=($3) # list of mixed-case email addresses for an alias

	start_log_capture

	local alice_pw="$(generate_password 16)"
	local bob_pw="$(generate_password 16)"
	# create local user alice and alias group
	if mgmt_assert_create_user "${alices[0]}" "$alice_pw"; then
		# test that alice cannot also exist at the same time
		if mgmt_create_user "${alices[1]}" "$alice_pw" no; then
			test_failure "Creation of a user with the same email address, but different case, succeeded."
			test_failure "${REST_ERROR}"
		fi
		
		# create an alias group with alice in it
		mgmt_assert_create_alias_group "${aliases[0]}" "${alices[1]}"
	fi

	# create local user bob
	mgmt_assert_create_user "${bobs[0]}" "$bob_pw"
	
	assert_check_logs
	

	# send mail from bob to alice
	#
	if ! have_test_failures; then
		record "[Mailing to alice from bob]"
		start_log_capture
		local output
		output="$($PYMAIL -to ${alices[2]} "$alice_pw" $PRIVATE_IP ${bobs[1]} "$bob_pw" 2>&1)"
		assert_python_success $? "$output"
		assert_check_logs

		# send mail from bob to the alias, ensure alice got it
		#
		record "[Mailing to alias from bob]"
		start_log_capture
		local subject="Mail-In-A-Box test $(generate_uuid)"
		output="$($PYMAIL -subj "$subject" -no-delete -to ${aliases[1]} na $PRIVATE_IP ${bobs[2]} "$bob_pw" 2>&1)"
		assert_python_success $? "$output"
		output="$($PYMAIL -subj "$subject" -no-send $PRIVATE_IP ${alices[3]} "$alice_pw" 2>&1)"
		assert_python_success $? "$output"
		assert_check_logs
		
		# send mail from alice as the alias to bob, ensure bob got it
		#
		record "[Mailing to bob as alias from alice]"
		start_log_capture
		local subject="Mail-In-A-Box test $(generate_uuid)"
		output="$($PYMAIL -subj "$subject" -no-delete -f ${aliases[2]} -to ${bobs[2]} "$bob_pw" $PRIVATE_IP ${alices[4]} "$alice_pw" 2>&1)"
		assert_python_success $? "$output"
		output="$($PYMAIL -subj "$subject" -no-send $PRIVATE_IP ${bobs[3]} "$bob_pw" 2>&1)"
		assert_python_success $? "$output"
		assert_check_logs
	fi

	mgmt_assert_delete_user "${alices[1]}"
	mgmt_assert_delete_user "${bobs[1]}"
	mgmt_assert_delete_alias_group "${aliases[1]}"
}


test_mixed_case_users() {
	# create mixed-case user anad domain names
	# add user to alias using different cases
	# send mail from another user to that user - validates smtp, imap, delivery
	# send mail from another user to the alias
	# send mail from that user as the alias to the other user

	test_start "mixed-case-users"
	
	local alices=(alice@mgmt.somedomain.com
				  aLICE@MGMT.somedomain.com
				  aLiCe@mgmt.SOMEDOMAIN.com
				  ALICE@mgmt.somedomain.COM
				  alIce@mgmt.SomeDomain.com)
	local bobs=(bob@mgmt.somedomain.com
				Bob@MGMT.somedomain.com
				boB@mgmt.SOMEDOMAIN.com
				BOB@mgmt.somedomain.COM)
	local aliases=(aLICE@MGMT.anotherdomain.com
				   aLiCe@mgmt.ANOTHERDOMAIN.com
				   ALICE@mgmt.anotherdomain.COM)

	_test_mixed_case "${alices[*]}" "${bobs[*]}" "${aliases[*]}"
	
	test_end
}


test_intl_domains() {
	test_start "intl-domains"

	# local intl alias
	local alias="alice@bücher.example"
	local alias_idna="alice@xn--bcher-kva.example"

	# remote intl user / forward-to
	local intl_person="hans@bücher.example"
	local intl_person_idna="hans@xn--bcher-kva.example"

	# local users
	local bob="bob@somedomain.com"
	local bob_pw="$(generate_password 16)"
	local mary="mary@somedomain.com"
	local mary_pw="$(generate_password 16)"

	start_log_capture

	# international domains are not permitted for user accounts
	if mgmt_create_user "$intl_person" "$bob_pw"; then
		test_failure "A user account is not permitted to have an international domain"
		# ensure user is removed as is expected by the remaining tests
		mgmt_delele_user "$intl_person"
		delete_user "$intl_person"
		delete_user "$intl_person_idna"
	fi
	
	# create local users bob and mary
	mgmt_assert_create_user "$bob" "$bob_pw"
	mgmt_assert_create_user "$mary" "$mary_pw"

	# create intl alias with local user bob and intl_person in it
	if mgmt_assert_create_alias_group "$alias" "$bob" "$intl_person"; then
		# examine LDAP server to verify IDNA-encodings
		get_attribute "$LDAP_ALIASES_BASE" "(mail=$alias_idna)" "rfc822MailMember"
		if [ -z "$ATTR_DN" ]; then
			test_failure "IDNA-encoded alias group not found! created as:$alias expected:$alias_idna"
		elif [ "$ATTR_VALUE" != "$intl_person_idna" ]; then
			test_failure "Alias group with user having an international domain was not ecoded properly. added as:$intl_person expected:$intl_person_idna"
		fi
	fi

	# re-create intl alias with local user bob only
	mgmt_assert_create_alias_group "$alias" "$bob"
	
	assert_check_logs

	if ! have_test_failures; then
		# send mail to alias from mary, ensure bob got it
		record "[Sending to intl alias from mary]"
		# note PYMAIL does not do idna conversion - it'll throw
		# "UnicodeEncodeError: 'ascii' codec can't encode character
		# '\xfc' in position 38".
		#
		# we'll have to send to the idna address directly
		start_log_capture
		local subject="Mail-In-A-Box test $(generate_uuid)"
		local output
		output="$($PYMAIL -subj "$subject" -no-delete -to "$alias_idna" na $PRIVATE_IP $mary "$mary_pw" 2>&1)"
		assert_python_success $? "$output"
		output="$($PYMAIL -subj "$subject" -no-send $PRIVATE_IP $bob "$bob_pw" 2>&1)"
		assert_python_success $? "$output"
		assert_check_logs
	fi

	mgmt_assert_delete_alias_group "$alias"
	mgmt_assert_delete_user "$bob"
	mgmt_assert_delete_user "$mary"

	test_end
}



test_totp() {
	test_start "totp"

	# alice
	local alice="alice@somedomain.com"
	local alice_pw="$(generate_password 16)"

	start_log_capture

	# create regular user alice
	mgmt_assert_create_user "$alice" "$alice_pw"

	# alice must be admin to use TOTP
	if ! have_test_failures; then
		# get an access token - we have to use the authorization code method
		# because alice is not an administrator
		assert_get_access_token "$alice" "$alice_pw" "" "code"
	fi
	
	if ! have_test_failures; then
		if mgmt_totp_enable "$alice" "$ACCESS_TOKEN"; then
			test_failure "User must be an admin get MFA status, but server allowed it"
		else
			# make alice an admin
			mgmt_assert_privileges_add "$alice" "admin"
		fi
	fi

	# add totp to alice's account (if successful, secret is in TOTP_SECRET)
	if ! have_test_failures; then
		# get a new access token that has updated claims now that
		# alice is admin
		assert_get_access_token "$alice" "$alice_pw"
		if ! have_test_failures; then
			mgmt_assert_totp_enable "$alice" "$ACCESS_TOKEN"
			# TOTP_SECRET and TOTP_TOKEN are now set...
		fi
	fi

	# logging in with just the password should now fail
	if ! have_test_failures; then
		record "Expect a login failure..."
		mgmt_assert_admin_login "$alice" "$alice_pw" "missing-totp-token"
	fi
	

	# logging into /auth/user/login with a password and totp code
	# should succeed - this is the endpoint the admin ui uses
	if ! have_test_failures; then		
		record "Try using a password plus a totp code, we may have to wait 30 seconds to get a new code..."

		if ! mgmt_get_totp_token "$TOTP_SECRET" "$TOTP_TOKEN"; then
			test_failure "Could not obtain a new TOTP token"
			
		else
			# we have a new totp code, try logging in ...
			# the code must be placed in the header "x-auth-token"
			if mgmt_assert_admin_login "$alice" "$alice_pw" "ok" "--header=x-auth-token: $TOTP_TOKEN"
			then
				record "Success: login with TOTP token successful"

				# ensure the totpMruToken was changed in LDAP
				get_attribute "$LDAP_USERS_BASE" "(mail=$alice)" "totpMruToken"
				if [ "$ATTR_VALUE" != "{0}$TOTP_TOKEN" ]; then
					record_search "(mail=$alice)"
					test_failure "totpMruToken wasn't updated in LDAP"
				fi
			fi
		fi
	fi

	# we should not be permitted to reuse TOTP codes. geting an
	# access token for alice should fail.
	if ! have_test_failures; then
		record "[Test that TOTP codes can't be reused]"
		if get_access_token "$alice" "$alice_pw" "$TOTP_TOKEN"; then
		   test_failure "TOTP code reuse should not be permitted"

		elif ! grep -F "invalid-totp-token" <<<"$ACCESS_TOKEN_ERROR" >/dev/null
		then
			test_failure "Unexpected error getting access_token: $ACCESS_TOKEN_ERROR"
		fi
	fi
	
	# ensure getting an access token with TOTP enabled works
	if ! have_test_failures; then
		record "Get a new TOTP code"
		if ! mgmt_get_totp_token "$TOTP_SECRET" "$TOTP_TOKEN"; then
			test_failure "Could not obtain a new TOTP token"
			
		else
			assert_get_access_token "$alice" "$alice_pw" "$TOTP_TOKEN"
		fi
	fi

	# perform a simple test to ensure an api call works
	if ! have_test_failures; then
		if ! mgmt_rest_bearer "GET" "/admin/mail/users" "$alice" "$ACCESS_TOKEN"
		then
			test_failure "Could not perform a simple user list test: $REST_ERROR"
		fi
	fi
	
	# disable totp on the account. ensure logging in with without TOTP
	# works. check that the ldap entry does not have the 'totpUser'
	# objectClass
	if ! have_test_failures; then		
		if mgmt_assert_mfa_disable "$alice" "$ACCESS_TOKEN"; then
			mgmt_assert_admin_login "$alice" "$alice_pw" "ok"
		fi
	fi

	# check for errors in system logs
	if ! have_test_failures; then
		assert_check_logs
	else
		check_logs
	fi
	
	mgmt_assert_delete_user "$alice"
	test_end
}

test_master_api_key() {
	test_start "master_api_key"
	local allow_api_key_login
	allow_api_key_login=$(jq .allow_api_key_login /var/lib/mailinabox/mgmt_oauth_config.json 2>&1)
	if [ $? -ne 0 ]; then
		die "Could not read /var/lib/mailinabox/mgmt_oauth_config.json: $allow_api_key_login"
	fi
	record "[test that master api key works as configured]"
	record "run: $MGMT_CLI user"
	record "allow_api_key_login='$allow_api_key_login'"
	local output code
	output="$($MGMT_CLI user 2>&1)"
	code=$?
	if [ "$allow_api_key_login" = "true" ]; then
		assert_python_success $code "$output"
	else
		assert_python_failure $code "$output" "system api key login is disabled"
	fi
	test_end
}


suite_start "management-users" mgmt_start

test_master_api_key
test_totp
test_mixed_case_users
test_intl_domains

suite_end mgmt_end

