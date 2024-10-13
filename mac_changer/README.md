#Key logger
To change the MAC address of a network interface, you need to install
the module pynput by typing on command line:
```bash
pip3 install argparse termcolor
```
or<br>
```bash
pip3 install -r requirements.txt
```
To run the program, you need to type for example this command on bash:
```bash
python3 mac_changer.py -i eth0 -hw 00:11:22:33:44:55 
```
An example of output of the command is shown in the following image:
![output](output.png)
To check which parameters you can insert, you can type the command:
```bash
python3 mac_changer.py --help 
```
The program must run with superuser privileges.
