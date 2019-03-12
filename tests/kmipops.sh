#!/bin/bash

function usage
{
    cat 1>&2 <<UsageMessage

Usage: $0 -u OP_USER -p OP_USER_PWD -c config_session
    -u operator user in HSM (will create a kmip user)
    -p operator user password
    -c config session in pykmip.conf to be used in the tests
    -h this help

UsageMessage

    exit 2
}

while getopts u:p:c: opt
do
    case "$opt" in
        u) HSM_TEST_USER="$OPTARG";;
        p) HSM_TEST_USER_PASSWD="$OPTARG";;
        c) conf_session="$OPTARG";;
        ?|h) usage
    esac
done

[[ -z "$HSM_TEST_USER" ]] && usage
[[ -z "$HSM_TEST_USER_PASSWD" ]] && usage
[[ -z "$conf_session" ]] && usage

#Global vars ... read only

declare -r pythonexe=/cygdrive/c/Python27/python.exe
declare -r unitspath=/projetos/dinamo/PyKMIP/kmip/demos/units
declare -r piepath=/projetos/dinamo/PyKMIP/kmip/demos/pie
declare -r config_session=kmip_test
declare -r outfile=out.txt
declare -r tst_pwd=12345678
declare -r kmip_user_cert=/projetos/dinamo/PyKMIP/tests/rsa2k_cert.pem

# the \\ bellow is the escape for grep

host=$(grep -A 12 \\[${conf_session}\\] ~/.pykmip/pykmip.conf | grep "host=" | sed "s/host=\(.*\)/\1/" )
user=$(grep -A 12 \\[${conf_session}\\] ~/.pykmip/pykmip.conf | grep "username=" | sed "s/username=\(.*\)/\1/" )
pass=$(grep -A 12 \\[${conf_session}\\] ~/.pykmip/pykmip.conf | grep "password=" | sed "s/password=\(.*\)/\1/" )

HSM_ADDR=${host}

echo host=${host}
echo user=${user}
echo pass=${pass}

PROG_NAME=hsmutil
EXEC_TESTER=${PROG_NAME}.exe

EXECLOGFILE=./execlogfile.txt

#
# Useful to know all the enums used by kmip:
#
# https://github.com/OpenKMIP/PyKMIP/blob/master/kmip/core/enums.py
#

function exec_line
{
    #parameters:
    #1: parameters to execute
    #2: expected result

    EXEC_LINE_CMD="$EXEC_TESTER -a $HSM_ADDR -u $HSM_USER -w $HSM_PASSWD"

    exec_full_line="${EXEC_LINE_CMD} $1"

    ${exec_full_line} >> $EXECLOGFILE

}

function setup_test
{
    # create a specific user to run the tests, this allowS some of the tests be
    # done on multiple clients simultaneously
    rand_str=`echo $RANDOM`

    TEST_WORKING_DIR="kmiptst_${rand_str}"
    mkdir ${TEST_WORKING_DIR}
    cd ${TEST_WORKING_DIR}

    #the user that will run the tests
    user_name="kmiptst${rand_str}"
    user_password=${tst_pwd}

    #the configured user that starts the test and create another user
    HSM_USER=${HSM_TEST_USER}
    HSM_PASSWD=${HSM_TEST_USER_PASSWD}

    echo -e "creating user ${user_name} for tests..."
    exec_line "-j create_user -usr ${user_name} -pwd ${user_password} -tls 1" 0

    exec_line "-j assignx509 -usr ${user_name} -filein ${kmip_user_cert} -tls 1" 0

    sed  "s/username=[^cvu].*/username=${user_name}/" -i ${HOME}/.pykmip/pykmip.conf

    #the tests will be done using the just created user
    HSM_USER=${user_name}
    HSM_PASSWD=${user_password}

    num_tests_kmip=$((0))
    num_fails_kmip=$((0))

    'rm' -f ${EXECLOGFILE} >/dev/null 2>&1

}

function clear_test_setup
{

    #the user that runs the test, it will be removed
    user_name=${HSM_USER}

    #the configured user that starts/ends the test and remote the users
    HSM_USER=${HSM_TEST_USER}
    HSM_PASSWD=${HSM_TEST_USER_PASSWD}

    #remove users in the HSM
    exec_line "-j remove_user -usr ${user_name}" 0

    #get the log of the tests
    #exec_line "-j get_log -fmt 1 -log logfile.txt" 0

    #clear temp folders
    cd ..
    #uncomment here if you need to persist the files generated by the tests
    rm -rf ${TEST_WORKING_DIR}

    #echo "testing user: ${user_name}"

    #exec_line "-j unassignx509 -usr ${user_name}" 0

}


function print_result
{
    # parameters
    # $1: result: 0:OK, not 0:FAIL

    echo -en "\n*** "

    if [ ${1} -eq 0 ] ; then
        echo -en "\033[32m  OK  \033[0m"
    else
        echo -en "\033[31m FAIL \033[0m"

        num_fails_kmip=$((num_fails_kmip + 1))
    fi

    echo -en " ***\n\n"
}

function test_kmip_output
{
    # parameters:
    # $1 : test_string

    grep ${1} ${outfile}

    print_result $?
}

function test_activate_revoke
{
    # parameters:
    # $1: key uuid

    # !!! NOTE: the key will be in revoked state after the test !!!

    run_kmip_test activate  "-i ${1}"
    run_kmip_test get_attributes "-i ${1}"
    test_kmip_output "State.ACTIVE"

    run_kmip_test revoke  "-i ${1}"
    run_kmip_test get_attributes "-i ${1}"
    test_kmip_output "State.DEACTIVATED"

}

function run_kmip_test
{
    # parameters
    # $1 : script to run (without extension)
    # $2 : script parameters

    kmip_script=${1}
    shift 1
    kmip_params=$@

    case ${kmip_script} in
        ( "register_certificate" | "register_opaque_object" | "register_symmetric_key" | \
           "get_attribute_list" | "get_attributes" | "encrypt3" | "decrypt3")
            script_path=${piepath}
            kmip_success_text="Successfully"
        ;;
        * )
            script_path=${unitspath}
            kmip_success_text="ResultStatus.SUCCESS"
        ;;
    esac

    ${pythonexe} ${script_path}/${kmip_script}.py -c ${config_session} ${kmip_params} 2>&1 | tee ${outfile}

    # sed regex will get confused with the \r, so we convert the out file the a unix line ending.
    sed -i 's/\r//g' "${outfile}"

    grep ${kmip_success_text} ${outfile}

    print_result $?

    num_tests_kmip=$((num_tests_kmip + 1))
}

function test_sym_key
{
    # parameters:
    # $1: key_type
    # $2: len list
    # $3: modes list
    # $4: paddings list

    #"        1         2         3          4         5"
    #"12345678901234567890123456789012345678901234567890"
    #"12345678123456781234567812345678"
    #"Mensagem que nao precisa padding"
    #"A message that needs no padding."
    #"A message for kmip encyption/decryption tests."

    regex_sym_key='s/.*INFO.*created UUID: \(.*\)/\1/p'

    for l in ${2}
    do
        run_kmip_test create "-a ${1} -l ${l}"
        kuuid=$(sed -n "${regex_sym_key}" "${outfile}")

        run_kmip_test get_attribute_list "-i ${kuuid}"
        run_kmip_test get "-i ${kuuid} -f RAW"
        run_kmip_test activate "-i ${kuuid}"
        run_kmip_test get_attributes "-i ${kuuid}"

        for m in ${3}
        do
            for p in ${4}
            do
                if [ "${p}" == "NONE" ]; then
                    tst_msg="12345678123456781234567812345678"

                else
                    tst_msg="123456781234567812345678123456781234"
                fi

                test_sym_encdec ${kuuid} ${tst_msg} ${m} ${p}
            done
        done

        run_kmip_test revoke  "-i ${kuuid}"
        run_kmip_test destroy "-i ${kuuid}"

    done
}

function test_asym_key_pair
{
    # parameters:
    # $1: key_name
    # $2: len list
    # $3: pri key format list
    # $4: pub key format list

    regex_priv_key="s/.*INFO.*private key.*UUID: \(.*\)/\1/p"
    regex_pub_key="s/.*INFO.*public key.*UUID: \(.*\)/\1/p"

    for l in ${2}
    do
        run_kmip_test create_key_pair "-a ${1} -l ${l} -n ${1}${l}"

        priv_uuid=$(sed -n "${regex_priv_key}" ${outfile})
        pub_uuid=$(sed -n "${regex_pub_key}" ${outfile})

        run_kmip_test get_attribute_list "-i ${priv_uuid}"
        run_kmip_test get_attribute_list "-i ${pub_uuid}"

        for f in ${3}
        do
            run_kmip_test get "-i ${priv_uuid} -f ${f}"
        done

        for f in ${4}
        do
            run_kmip_test get "-i ${pub_uuid} -f ${f}"
        done

        test_activate_revoke "${priv_uuid}"
        test_activate_revoke "${pub_uuid}"

        run_kmip_test destroy "-i ${priv_uuid}"
        run_kmip_test destroy "-i ${pub_uuid}"
    done

}

function test_sym_encdec
{
    # parameters:
    # $1: key uuid
    # $2: message
    # $3: mode
    # $4: paddding

    regex_cipher_msg="s/.*INFO.*Cipher text.*: \(.*\)/\1/p"
    regex_iv="s/.*INFO.*Autogenerated IV.*: \(.*\)/\1/p"
    regex_clear_msg="s/.*INFO.*Plain text.*: '\(.*\)'/\1/p"

    run_kmip_test encrypt3 "-i ${1} -m ${2} -d ${3} -a ${4}"

    cipher_msg=$(sed -n "${regex_cipher_msg}" ${outfile})
    iv=$(sed -n "${regex_iv}" ${outfile})

    # note: -m and -v are binaries, so the 'b'
    run_kmip_test decrypt3 "-i ${1} -m b${cipher_msg} -d ${3} -a ${4} -v b${iv}"

    clear_msg=$(sed -n "${regex_clear_msg}" ${outfile})

    if [ "${2}" != "${clear_msg}" ] ; then

        echo "Symmetric encryption and descryption, comparison fails !"
        print_result 1
    fi

}

function test_keys
{
    # parameters:

    test_sym_key "DES"          "56"          "ECB CBC"     "NONE ZEROS PKCS5"

    test_sym_key "TRIPLE_DES"   "112 168"     "ECB CBC"     "NONE ZEROS PKCS5"

    test_sym_key "AES"          "128 192 256" "ECB CBC"     "NONE ZEROS PKCS5"

    #testar padds
    # ANSI_X923 : simetrico
    # X931       : assimetrico

    test_asym_key_pair "RSA"\
                        "1024 2048"\
                        "PKCS_1 PKCS_8"\
                        "RAW PKCS_1"

    test_asym_key_pair "EC"\
                        "192 224 256 384 521"\
                        "PKCS_8"\
                        "RAW"

                        # ECC xp/st: "192 224 256 384 521"\
                        # ECC pocket: "192 224"\

}

function register_and_get
{
    regex_reg_uuid="s/.*INFO.*Successfully.*registered.*ID: \(.*\)/\1/p"

    ###### certificate ######

    run_kmip_test register_certificate
    kuuid=$(sed -n "${regex_reg_uuid}" ${outfile})

    run_kmip_test get_attribute_list "-i ${kuuid}"

    for f in X_509
    do
        run_kmip_test get "-i ${kuuid} -f ${f}"
    done

    run_kmip_test destroy "-i ${kuuid}"

    ###### sym key ######

    run_kmip_test register_symmetric_key
    kuuid=$(sed -n "${regex_reg_uuid}" ${outfile})

    run_kmip_test get_attribute_list "-i ${kuuid}"

    for f in RAW
    do
        run_kmip_test get "-i ${kuuid} -f ${f}"
    done

    run_kmip_test destroy "-i ${kuuid}"

    ############

    return 0
}

### tests begin here  ###
test_begin_time=`date +%s`

setup_test

run_kmip_test query

run_kmip_test discover_versions

test_keys

register_and_get

### tests ends here ###
clear_test_setup

echo
echo
echo "Num. of KMIP Tests: $num_tests_kmip"
echo "Num. of Failed KMIP Tests: $num_fails_kmip"

test_end_time=`date +%s`
((diff_sec=test_end_time-test_begin_time))
echo - | awk '{printf "\n\nTest duration: %02d:%02d:%02d\n\n","'"$diff_sec"'"/(60*60),"'"$diff_sec"'"%(60*60)/60,"'"$diff_sec"'"%60}'
