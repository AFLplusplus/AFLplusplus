#default values
timeout_sec=5
LD_PRELOAD_PATH="/home/${USER}/AFLplusplus/utils/libtokencap/libtokencap.so"

#help
usage() {
    echo "Usage: $0 -o <target_output> -b <target_bin> [-t <timeout_sec>] [-p <LD_PRELOAD_PATH>]"
    echo "Options:"
    echo "  -o  Path to target output directory"
    echo "  -b  Path to target program binary"
    echo "  -t  Timeout in seconds (default: 5)"
    echo "  -p  Path to LD_PRELOAD library (default: ${LD_PRELOAD_PATH})"
    exit 1
}

#parse cli options
while getopts ":o:b:t:p:" opt; do
    case $opt in
        o) target_output="$OPTARG" ;;
        b) target_bin="$OPTARG" ;;
        t) timeout_sec="$OPTARG" ;;
        p) LD_PRELOAD_PATH="$OPTARG" ;;
        \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
        :) echo "Option -$OPTARG requires an args" >&2; usage ;;
    esac
done

#check options
if [ -z "$target_output" ] || [ -z "$target_bin" ]; then
    echo "Error: Missing mandatory opts" >&2
    usage
fi

# initialize vars
AFL_TOKEN_FILE="${PWD}/temp_output.txt"
AFL_DICT_FILE="$(basename "$target_output").dict"

#generate token-file
{
    touch "$AFL_TOKEN_FILE"
    for i in $(find "$target_output" -type f -name "id*"); do
        LD_PRELOAD="$LD_PRELOAD_PATH" \
        timeout -s SIGKILL "$timeout_sec" \
        "$target_bin" "$i"
    done
} >"$AFL_TOKEN_FILE"

# sort & remove duplicates
sort -u "$AFL_TOKEN_FILE" >"$AFL_DICT_FILE"
