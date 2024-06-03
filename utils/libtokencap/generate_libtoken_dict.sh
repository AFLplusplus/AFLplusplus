#help
usage() {
    echo "Usage: $0 -o <target_output> -b <target_bin> -p <LD_PRELOAD_PATH> [-t <timeout_sec>] -- [target_args]"
    echo "Options:"
    echo "  -o  Path to target output directory"
    echo "  -b  Path to target program binary"
    echo "  -p  Path to LD_PRELOAD library"
    echo "  -t  Timeout in seconds"
    exit 1
}

#parse cli options
while getopts ":o:b:p:t:" opt; do
    case $opt in
        o) target_output="$OPTARG" ;;
        b) target_bin="$OPTARG" ;;
        p) LD_PRELOAD_PATH="$OPTARG" ;;
        t) timeout_sec="$OPTARG" ;;
        \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
        :) echo "Option -$OPTARG requires an argument." >&2; usage ;;
    esac
done

#shift away the parsed opts
shift $((OPTIND - 1))

#check options
if [ -z "$target_output" ] || [ -z "$target_bin" ] || [ -z "$LD_PRELOAD_PATH" ]; then
    echo "Error: Missing mandatory opts" >&2
    usage
fi

# initialize vars
AFL_TOKEN_FILE="${PWD}/temp_output.txt"
AFL_DICT_FILE="${PWD}/$(basename "$target_bin")_tokens.dict"

#generate token-file
{
    touch "$AFL_TOKEN_FILE"
    for i in $(find "$target_output" -type f -name "id*"); do
        LD_PRELOAD="$LD_PRELOAD_PATH" \
        timeout -s SIGKILL "$timeout_sec" \
        "$target_bin" "$@" "$i"
    done
} >"$AFL_TOKEN_FILE"

# sort & remove duplicates
sort -u "$AFL_TOKEN_FILE" >"$AFL_DICT_FILE"

# delete temp-file
rm "$AFL_TOKEN_FILE"

# print done-message
echo "Token dictionary created: $AFL_DICT_FILE"
echo "Script completed successfully"
