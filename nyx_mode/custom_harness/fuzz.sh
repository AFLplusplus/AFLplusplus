chmod +x hget
cp hget /tmp/
cd /tmp/
echo 0 > /proc/sys/kernel/randomize_va_space
echo 0 > /proc/sys/kernel/printk
./hget hcat hcat
./hget habort habort
./hget target target
chmod +x hcat
chmod +x habort
chmod +x target
./target
./habort "Target has terminated without initializing the fuzzing agent ..."
