

test_ehdd_restart() {
    test_start "ehdd-restart"

    # a keyfile must be in use, to avoid user interaction
    if [ -z "$EHDD_KEYFILE" ]; then
        test_failure "EHDD_KEYFILE must be set"
        test_end
        return
    fi

    # the keyfile must exist
    if [ ! -e "$EHDD_KEYFILE" ]; then
        test_failure "Keyfile path '$EHDD_KEYFILE' does not exist"
        test_end
        return
    fi
    
    # shutdown and unmount
    local rc=0
    pushd .. >/dev/null

    record "[Run ehdd/shutdown.sh]"
    ehdd/shutdown.sh >>$TEST_OF 2>&1
    [ $? -ne 0 ] && test_failure "Could not unmount encryption-at-rest drive"

    # startup
    record "[Run ehdd/startup.sh]"
    ehdd/startup.sh >>$TEST_OF 2>&1
    [ $? -ne 0 ] && test_failure "Could not start encryption-at-rest"

    popd >/dev/null
    
    test_end
}



suite_start "ehdd"

test_ehdd_restart

suite_end
