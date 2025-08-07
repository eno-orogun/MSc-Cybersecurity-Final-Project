<h1>VM Setup Documentation</h1>
A virtual machine (VM) was created using Ubuntu Desktop 22.04 with two network adapters– one set to NAT to give it internet access and the other set to Bridged Network which enables access to the physical LAN.  The VM was assigned the NAT interface (enp0s3) which has an IPv4 automatic DHCP IP Address (10.0.2.15).

The following applications were then installed on the VM:
1.	Android Studio – Android Emulator
2.	JADX
3.	Android Debug Bridge -ADB
4.	MobSF -Mobile Security Framework
5.	Autopsy
6.	SQLite

<h1>Android Studio Installation</h1>
Before Android studio could be installed on the VM, the dependencies such as Open JDK needed to be installed – this was achieved by running the command to update the local package index first followed by the command to install the OpenJDK: 

sudo apt update
sudo apt install openjdk-17-jdk unzip curl git

On completion of install the command – Android-studio was run in Ubuntu terminal to startup the application and the onscreen steps were followed to complete the setup.

<h1>JADX installation</h1>
The version of Java installed was confirmed with the command:

java -version

JADX was then downloaded from JADX GitHub Releases using the latest .zip file.
In the ubuntu terminal the following command was used to unzip the JADX zip file but first navigating to the Downloads directory where the JADX files are saved:

cd Downloads/
sudo unzip jadx-1.5.2.zip
Then running JADX GUI with the following commands:

./bin/jadx-gui


<h1>Android Debug Bridge -ADB</h1>

ADB was installed by first running the command to update the local package index first followed by the command to install ADB tool:

sudo apt update
sudo apt install android-tools-adb
The installation was verified by running the command:

adb version

<h1>MobSF - Mobile Security Framework Installation</h1>

Docker was installed, then started and enabled before MobSF could be installed – using the commands:

sudo apt install docker .io -y
sudo systemctl start docker
sudo systemctl enable docker

MobSF installed using the command:
sudo docker pull opensecurity/mobile-security-framework-mobsf

Then running MobSF using the command in ubuntu terminal:
sudo docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
Finally opening a web browser to view MobSF at http://localhost:8000
A username and password mobsf/mobsf were used to sign in.

<h1>Autopsy Installation</h1>

Autopsy was installed on the VM by running the command:

sudo snap install autopsy # version 4.22.1

Autopsy was started by running the command in ubuntu terminal:
cd Downloads/
autopsy

Then opening a web browser and navigating to http://localhost:9999

<h1>SQLite Installation</h1>

SQLite was installed with the command:

sudo apt install sqlite3
The SQLite browser was then installed using the command:
sudo apt install sqlitebrowser
The application was started using the command:
sqlitebrowser


 
