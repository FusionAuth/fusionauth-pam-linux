To run Vagrant for testing, run these commands from the `test` directory:

1. `brew install vagrant`
2. `vagrant plugin install vagrant_utm`
3. `vagrant up`
4. `vagrant ssh`
5. `sudo apt-get update`
6. `sudo apt-get install gcc make libcurl4-openssl-dev libjson-c-dev libpam0g-dev`

Enjoy!

Once you have Vagrant running, you can run `make all` from the `fusionauth-pam-linux` directory. After the compiler finishes, you can run `sudo make install` to install the PAM module. And finally, you can run `sudo make uninstall` to uninstall the PAM module.