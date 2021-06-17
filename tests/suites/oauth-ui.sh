# -*- indent-tabs-mode: t; tab-width: 4; -*-
#	
# OAuth ui tests
#



test_roundcube_login() {
	test_start "roundcube-login"

	# alice
	local alice="alice@somedomain.com"
	local alice_pw="$(generate_password 16)"

	start_log_capture

	# create alice
	create_user "$alice" "$alice_pw"

    # test login
	record "[launching selenium test roundcube-oauth-login.py]"
    local output
	output=$(python3 suites/ui/roundcube-oauth-login.py "$alice" "$alice_pw" 2>&1)
	local code=$?
	record "$output"
	if [ $code -ne 0 ]; then		
		test_failure "unable to login using oauth: $(python_error "$output")"
	fi
    
    # clean up
    delete_user "$alice"
    test_end
}



suite_start "oauth-ui"

test_roundcube_login

suite_end


