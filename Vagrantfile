Vagrant.configure("2") do |vagrant_config|
  
	windows_servers_config = {
		'dc' => {
			:ip => '192.168.1.100',
			:image => 'StefanScherer/windows_2019'
		},
		
		'win_server' => {
			:ip => '192.168.1.101',
			:image => 'StefanScherer/windows_2019'
		},
		
		'win_workstation' => {
			:ip => '192.168.1.102',
			:image => 'StefanScherer/windows_10'
		}
	}
  
	vagrant_config.vm.provider "vmware_workstation" do |v|
		v.memory = 1500
		v.cpus = 1
	end
    
	windows_servers_config.each_with_index do |(server_name, server_config), i|

		vagrant_config.vm.define server_name do |windows_box_config|

			windows_box_config.vm.guest = :windows
			windows_box_config.vm.communicator = "winrm"
			windows_box_config.vm.boot_timeout = 240
			windows_box_config.vm.graceful_halt_timeout = 240
			windows_box_config.winrm.retry_limit = 5
			windows_box_config.winrm.retry_delay = 10
			windows_box_config.vm.box = server_config[:image]
			# configure network adaptater for windows not supported if provider is vmware ?
			windows_box_config.vm.network "public_network", ip: server_config[:ip]

			# configure network adaptater for windows not supported if provider is vmware ?
			windows_box_config.vm.provision :shell do |shell|
				shell.inline = "netsh interface ip set address name=\"Ethernet1\" static #{server_config[:ip]} 255.255.255.0"
				shell.powershell_elevated_interactive = true
				shell.privileged = true
			end
			
			windows_box_config.vm.provision :shell do |shell|
				shell.inline = "NetSh Advfirewall set allprofiles state off"
				shell.powershell_elevated_interactive = true
				shell.privileged = true
			end
			
			windows_box_config.vm.provision :shell do |shell|
				shell.inline = 'Set-WinUserLanguageList -LanguageList fr-FR -Force'
				shell.reboot = true
			end

			windows_box_config.vm.provision "shell", path:"ConfigureRemotingForAnsible.ps1"
		end 
		
	end 

end
