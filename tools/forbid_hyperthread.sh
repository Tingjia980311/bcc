for i in `seq 8 31`
do
    echo "output: $i"
    echo $1 > /sys/devices/system/cpu/cpu$i/online
done
