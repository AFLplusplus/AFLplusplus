chmod +x hget
cp hget /tmp/
cd /tmp/
echo 0 > /proc/sys/kernel/randomize_va_space
echo 0 > /proc/sys/kernel/printk
./hget hcat_no_pt hcat
./hget habort_no_pt habort
./hget target target
chmod +x hcat
chmod +x habort
chmod +x target
./target
./habort "Target has terminated without initializing the fuzzing agent ..."
