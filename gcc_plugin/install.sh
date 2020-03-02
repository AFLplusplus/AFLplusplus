var=$(gcc --version | grep ^gcc | sed 's/^.* //g')
echo "$var"
X=${var:0:1}
run="sudo apt install gcc-${X}-plugin-dev"
eval $run