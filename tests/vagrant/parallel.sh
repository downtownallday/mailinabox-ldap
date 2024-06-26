#!/bin/bash
#####
##### This file is part of Mail-in-a-Box-LDAP which is released under the
##### terms of the GNU Affero General Public License as published by the
##### Free Software Foundation, either version 3 of the License, or (at
##### your option) any later version. See file LICENSE or go to
##### https://github.com/downtownallday/mailinabox-ldap for full license
##### details.
#####


# Parallel provisioning for virtualbox because "The Vagrant VirtualBox
# provider does not support parallel execution at this time"
# (https://www.vagrantup.com/docs/providers/virtualbox/usage.html)
#
# Credit to:
#    https://dzone.com/articles/parallel-provisioning-speeding
#

. "$(dirname "$0")/../lib/color-output.sh"
. "$(dirname "$0")/../lib/misc.sh"

if [ -z "$tests" ]; then
    export tests="pre-commit"
fi


OUTPUT_DIR=out
#rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# set total parallel vms to (#cores minus 1)
MAX_PROCS=$(cat /proc/cpuinfo | grep processor | wc -l)
let MAX_PROCS-=1

 
parallel_provision() {
    while read box; do
        outfile="$OUTPUT_DIR/$box.out.txt"
        rm -f "$outfile"
        echo "Provisioning '$box'. Output will be in: $outfile" 1>&2
        echo $box
    done | xargs -P $MAX_PROCS -I"BOXNAME" \
        sh -c 'vagrant provision BOXNAME >'"$OUTPUT_DIR/"'BOXNAME.out.txt 2>&1 && echo "EXITCODE: 0" >> '"$OUTPUT_DIR/"'BOXNAME.out.txt || echo "EXITCODE: $?" >>'"$OUTPUT_DIR/"'BOXNAME.out.txt'
}
 
## -- main -- ##

start_time="$(date +%s)"

# start boxes sequentially to avoid vbox explosions
vagrant up --no-provision
 
# but run provision tasks in parallel
boxes="$(vagrant status | awk '/running \(/ {print $1}')"
echo "$boxes" | parallel_provision


# output overall result - Vagrantfile script must output "EXITCODE: <num>"
H1 "Results"

rc=0
for box in $boxes; do
    file="$OUTPUT_DIR"/$box.out.txt
    exitcode="$(tail "$file" | grep EXITCODE: | awk '{print $NF}')"
    echo -n "$box: "
    if [ -z "$exitcode" ]; then
        danger "NO EXITCODE!"
        [ $rc -eq 0 ] && rc=2
    elif [ "$exitcode" == "0" ]; then
        success "SUCCESS"
    else
        danger "FAILURE ($exitcode)"
        rc=1
    fi
done

# output elapsed time
end_time="$(date +%s)"
echo ""
echo "Elapsed time: $(elapsed_pretty $start_time $end_time)"

# exit
echo ""
echo "Guest VMs are running! Destroy them with 'vagrant destroy -f'"
exit $rc
