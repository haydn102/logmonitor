primary = fork do
    #==================================================================================
    #                                                                                ==
    #                                                           ##    ## ######      ==
    #    Sentinel Program MK2 (LINUX) (WATCHTOWER)              ##    ## ##   ##     ==
    #                                                           ##    ## ##    ##    ==
    #    Haydn Dungey (c) - 15-8-16                             ##    ## ##    ##    ==
    #     - EXPLANATION: program scans relevant OS logs and     ######## ##    ##    ==
    #       command output for syntax indicative of a hack      ##    ## ##    ##    ==
    #    Built for Linux                                        ##    ## ##    ##    ==
    #     - Last Mod - 26/4/19                                  ##    ## ##   ##     ==
    #                                                           ##    ## ######      ==
    #                                                                                ==
    # =================================================================================

    # ========================================================================
    # FOR ADDING ADDITIONAL SEARCH PROTOCOLS:
    #   - Push to @SEARCH_ARRAY below with variables pertaining to STRUCT:searchcommand_struct
    #
    # FOR ADDING ADDITIONAL LOG FILES:
    #   - Append log file location/name.log to @LOGFILE_STORE
    # ========================================================================

    @scriptname = $0
    @cwd = `pwd`
    @sleep_increment = 2    # pause time between search loops
    @user = `whoami`
    @master_width = 105     # cmd UI display width
    @looplatency_cap = 0.02 # sleep time between multiple-operations to cater for discrepancy
    @errorStore = []        # storing sys report details for postumous display
    @SEARCH_ARRAY = []      # contains static data on all search items (manually added below)
    @FileSTRUCT_array = []  # contains iteratively updated details on all files (manually added below)

    # ==== INPUT ARGUMENTS ====
    silentmode_inputpar = ARGV[0] # if true, will not print results, and will run in the background
    # =========================
    
    # ==== FUNCTIONAL VARIABLES ====
    @main_logfile   = "WATCHTOWER_verboseLog.txt" # verbose log including captured log output
    @event_logfile  = "WATCHTOWER_eventlog.txt"  # Basic log with :generalname events
    @status_file    = "WATCHTOWER_statuslog.txt"   # Running summary data

    # MUST CONTAIN ROOT PATH
    @LOGFILE_STORE = [
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/gufw.log",
        "/var/log/fail2ban.log",
        "/var/log/clamav/freshclam.log"]

    @SERVICESTATUS_CHECK = [
        "fail2ban",
        "psad",
        "ufw"]
    # ==============================

    # ==== SEARCH ITEMS =======
    # - All search items will be detailed below:
    # PARAMETERES: ========================
    # - Programable options which are supplied as stings and understood at processing level.
    #   SYNTAX: command item | command item | command item
    #    - must have spaces all around
    # - ignore syntax - will ignore search command result if ignore syntax is included.

    Logfile_struct = Struct.new(:filenamelocation,:prev_filelinecount,:standdown,:disparity)
    Searchcommand_struct = Struct.new(:generalname,:filebyindex,:windowalert_bool,:hitcount,:search_syntax,:alert_message,:parameters)
   
    # :generalname              Display name for search operation
    # :filebyindex              Specify target logfile in @LOGFILE_STORE by it's index number
    # :windowalert_bool         (Gnome only) show windowed alert
    # :hitcount                 SET TO 0, incrementing counter for each alert
    # :search_syntax            EXACT substring match on target logfile
    # :alert_message            (Gnome only) system libnotify alert message
    # :parameters               See description above

    # ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    # //// CONFIGURE ALERT SEARCH ITEMS HERE 
    # ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    #                                          |                              | filebyindex          |                                                    |
    #                                          |                              | windowalert_bool     |                                                    |
    #                                          | ItemTitle                    | hitcount             | search_syntax                                      | alert_message                           aditional parameters
    @SEARCH_ARRAY.push(Searchcommand_struct.new("Terminal session",             0,false,0,	          "New session",                                        "New Terminal session DETECTED"))
    @SEARCH_ARRAY.push(Searchcommand_struct.new("Failed SU Invoke",             0,false,0,		      "FAILED su",                                          "Failed su session invoke DETECTED"))
    @SEARCH_ARRAY.push(Searchcommand_struct.new("SSH auth Faliure",             0,false,0,            "pam_unix(sshd:auth): authentication failure",        "SSH authentication faliure DETECTED"))
    @SEARCH_ARRAY.push(Searchcommand_struct.new("SSH Password Faliure",         0,false,0,		      "sshd.*: Failed password for",                        "SSH Password faliure DETECTED"))
    @SEARCH_ARRAY.push(Searchcommand_struct.new("SUDO auth Faliure",            0,false,0,            "pam_unix(sudo:auth): authentication failure",        "SUDO authentication faliure DETECTED"))
    @SEARCH_ARRAY.push(Searchcommand_struct.new("Lockscreen - Login Faliure",   0,true,0,             "(gnome-screensaver:auth): authentication failure",   "GNOME Lockscreen - Login Failure DETECTED"))
    @SEARCH_ARRAY.push(Searchcommand_struct.new("UFW Disable",                  0,true,0,             "COMMAND=/usr/sbin/ufw disable",                      "UFW Disable DETECTED"))
    @SEARCH_ARRAY.push(Searchcommand_struct.new("UFW Enable",                   0,false,0,            "COMMAND=/usr/sbin/ufw enable",                       "UFW Enable DETECTED"))
    @SEARCH_ARRAY.push(Searchcommand_struct.new("PSAD - PortScan",              1,false,0,            "psad: scan detected",                                "Port Scan Detected",           "ignore 224.0.0.1 | ignore 224.0.0.251"))     # configured not to alarm if multicast 224.0.0.1 05 .251
    @SEARCH_ARRAY.push(Searchcommand_struct.new("PSAD - IP Tables AutoBlock",   1,false,0,            "psad: added iptables auto-block",                    "PSAD IP enforcement DETECTED"))
    @SEARCH_ARRAY.push(Searchcommand_struct.new("Fail2ban BAN enforcement",     3,true,0,             "NOTICE  [sshd] Ban",                                 "Fail2ban BAN enforcement DETECTED"))   
    @SEARCH_ARRAY.push(Searchcommand_struct.new("ClamAV Update started",        4,false,0,            "ClamAV update process started at",                   "ClamAV update process started at"))
    # ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    @silent_mode = @silent_mode.to_s

    print "RECEIVED #{silentmode_inputpar}"

    if silentmode_inputpar == "true"
        @silent_mode = true
    else
        @silent_mode = false
    end

    def heading_function(submission) # header length [50] | submission = heading name
        heading_length = @master_width
        header = "="

        heading_length.times do
            print header
        end

        print "\n"
        endform = "==== #{submission} "
        remainder = heading_length - endform.length
        print endform

        remainder.times do
            print header
        end
        print "\n"
    end

    def parameter_processing(string,search_syntax) # invoke and supply parameter string and current logfile syntax
        parameters = []
        if string.include?('|')
            parameters = string.split('|')
        else
            parameters = parameters.push(string)
        end

        length = parameters.length
        counter = 0
        while counter < length
            item = parameters[counter]
            item = item.rstrip
            item = item.lstrip

            div = item.split(' ')
            first = div[0]
            last = div[1]

            if (first == "ignore") && (search_syntax.include? last)
                sleep 0.5
                return "ignore" # return ignore status
            end
            counter = counter + 1
        end

        return 0 # return nil/fail status
    end

    # checks file for syntax
    # - File denoted by index supplied as function parameter
   
    def search_protocol(fileindex,target_syntax,hit_count,alert_message,windowalert_bool,searchItemIndex)      
            time = Time.new
            detection_match_string = "DETECTION CONFIRMED"
            detection_nomatch_string = "Status - Normal"

            file_disparity = @FileSTRUCT_array[fileindex].disparity
            standdown_mode = @FileSTRUCT_array[fileindex].standdown
            filename = @FileSTRUCT_array[fileindex].filenamelocation
            protocolname = @SEARCH_ARRAY[searchItemIndex].generalname
            parameterstring = @SEARCH_ARRAY[searchItemIndex].parameters

            # Disparity variable determins search depth for program in file
            syntax_check = `tail -#{file_disparity} #{filename} | grep "#{target_syntax}"`

            if standdown_mode == false 
                # ////////////////////////////////////////////////////               
                # ////////////////////////////////////////////////////              
                if syntax_check.include? target_syntax # <= magic !!
                    verdict = detection_match_string
                    if parameterstring != nil
                        if parameter_processing(parameterstring,syntax_check) == "ignore" # will standdown IF Detection match BUT ignore parameters are met
                            verdict = "STANDDOWN"
                        end
                    end
                    @SEARCH_ARRAY[searchItemIndex].hitcount = @SEARCH_ARRAY[searchItemIndex].hitcount + 1
                else
                    verdict = detection_nomatch_string
                end
                # ////////////////////////////////////////////////////
                # ////////////////////////////////////////////////////              
            else
                verdict = detection_nomatch_string
            end

            print_string = ""
            print_string += output_format("   - [#{filename}] ",30,' ')
            print_string += output_format(" PROTOCOL [#{protocolname}] ",35,' ')
            print_string += output_format(" [#{hit_count}]",7,' ')
            print_string += output_format(" [#{verdict}]",20,' ')
            print_string += output_format(" [#{standdown_mode}]",7,' ')
            @output_temp.push(print_string)

            if @silent_mode == false
                print "\n"
                print print_string
            end

            # GIU BANNER ALERT DETAILS
            if standdown_mode == false
                if verdict == detection_match_string

                    # Pertains to error heading display
                    # SELECTS SINGLE MATCH INSTANCE TO DISPLAY, NOT FULL ERROR REPORT (MULTILINE)
                    if @silent_mode == false
                        # if file_disparity > 1
                        #     synlist = syntax_check.split("\n")
                        #     syntax_ammended = synlist[0]
                        #     syntax_ammended = syntax_ammended.rstrip
                        # else
                        #     syntax_ammended = syntax_check
                        #     syntax_ammended = syntax_ammended.rstrip
                        # end
                        @errorStore = @errorStore.push(alert_message)
                    end
                    
                    form = "notify-send WATCHTOWER \"ALLERT: #{alert_message} !!\""
                    system form
                    form = "echo \"[#{syntax_check.rstrip}]\" >> /home/#{@user.rstrip}/#{@main_logfile}"
                    system form
                    form = "echo \"[#{`date`.rstrip}] - #{alert_message.rstrip}\" >> /home/#{@user.rstrip}/#{@event_logfile}"
                    system form

                    if windowalert_bool == true
                        #form = "zenity --warning --text \"WATCHTOWER: #{alert_message} [#{syntax_check}]\";"
                        # ^ old form not used, new below v

						#command = `egrep -A 4 '#{target_syntax}' #{filename} | tail -6`
						# ^ this command is good to parse out relevant data for lockscreen auth fail
						form = "zenity --info --width=1000 --height=200 --text=\"<big>WATCHTOWER: #{alert_message}</big> \\n\\n #{syntax_check}\""
                        system form
                    end

                    return 1
                else
                    return 0
                end

            else
                return 0
            end
    end

    def output_format(string,assigned_length,illustrator)

        master_string = ""        
        remainder = 1
        if assigned_length > string.length
            remainder = assigned_length - string.length

        elsif assigned_length < string.length
            diff = string.length - assigned_length
            string = string[0...-diff]
            remainder = 0

        end

        master_string.concat(string)
        
        remainder.times do
            master_string.concat(illustrator)
        end

        return master_string
    end

    def filepresence_check(file)
        division = file.split('/')
        filediv = division.last
        route = file.chomp(filediv)
        checkfile = `cd #{route};ls`

        if checkfile.include? filediv
            return 1
        end

        return 0
    end

    # === OPERATIONAL FUNCTIONS ============================================================================================

    def standard_operation
        totalloop_iteration = 0
        
        # Below chunk envokes previous linecount, and fills array with logfile STRUCT data
        # - Array contains STRUCTs per index
        counter = 0
        while counter < @LOGFILE_STORE.length
            file = @LOGFILE_STORE[counter]
            linecount = `wc -l #{file}`
            linecount = linecount.to_i

            # generates data structure and assigns to array, array will be referenced thoughout program operation
            filestruct = Logfile_struct.new(@LOGFILE_STORE[counter],linecount,true,1)
            @FileSTRUCT_array = @FileSTRUCT_array.push(filestruct)

            counter = counter + 1
        end

        while true
        	# array (wipes every loop) contains output from functionality, dumps in file.
        	@output_temp = []

            # PRELIM RESET ----------------
            sleep @sleep_increment
            if @silent_mode == false
                system ("clear")
            end
            time = Time.new
            if @errorStore.length > 60
                @errorStore = []
                if true # delimited because it was causing crashes, fix and reinvoke later by removing false statement
                    difference = @errorStore.length - 20
                    difference.times do 
                        @errorStore = @errorStore.shift
                    end
                end
            end
            if @silent_mode == false
                heading_function("[#{@scriptname}] OPERATION | Time: [#{time}] | Iteration: [#{totalloop_iteration}]")
            end


            # WHILE loop redefines standdown modes dependant on file linecount change ----------------
            counter = 0
            while counter < @LOGFILE_STORE.length

                file = @LOGFILE_STORE[counter]
                linecount = `wc -l #{file}`
                linecount = linecount.to_i
                if linecount == @FileSTRUCT_array[counter].prev_filelinecount
                    @FileSTRUCT_array[counter].standdown = true
                else
                    @FileSTRUCT_array[counter].standdown = false
                    @FileSTRUCT_array[counter].disparity = (linecount - @FileSTRUCT_array[counter].prev_filelinecount)
                end

                counter = counter + 1
            end


            # ////////////////////////////////////////////////////
            # ////////////////////////////////////////////////////
            counter = 0
            while counter < @SEARCH_ARRAY.length
                # Note that other file-specific values are pulled from @logfile_struct STRUCT details once file is identified
                search_protocol(
                    @SEARCH_ARRAY[counter].filebyindex,
                    @SEARCH_ARRAY[counter].search_syntax,
                    @SEARCH_ARRAY[counter].hitcount,
                    @SEARCH_ARRAY[counter].alert_message,
                    @SEARCH_ARRAY[counter].windowalert_bool,
                    counter)

                counter = counter + 1
            end
            # ////////////////////////////////////////////////////
            # ////////////////////////////////////////////////////


            # UPDATES PREV-LINECOUNT VALUES IN ALL STRUCTS ----------------
            counter = 0
            while counter < @LOGFILE_STORE.length
                file = @FileSTRUCT_array[counter].filenamelocation
                linecount = `wc -l #{file}`
                linecount = linecount.to_i

                if false
                    print "\n"
                    print " "
                    print @FileSTRUCT_array[counter].prev_filelinecount
                    print "-"
                    print linecount
                end

                @FileSTRUCT_array[counter].prev_filelinecount = linecount
                counter = counter + 1
            end


            # Displays err report headers ----------------
            if @silent_mode == false
                print "\n"
                length = @errorStore.length
                if length <= 5
                    counter = 0
                    while counter < @errorStore.length
                        print "\n      - [#{@errorStore[counter]}]"
                        counter = counter +1
                    end
                elsif length > 5
                    counter = 1
                    while counter <= 5
                        print "\n      - [#{@errorStore[-counter]}]"
                        counter = counter + 1
                    end
                else
                end
            end

            # only initiates every 10 iterations
            if totalloop_iteration % 10 == 0
	            # wipe file
	            form = "echo > /home/#{@user.rstrip}/#{@status_file}"
                #form = "echo > #{@status_file}"
	            system form

	            # finally dump @output_temp to file
				File.open("/home/#{@user.rstrip}/#{@status_file}", "w+") do |f|
				  f.puts(@output_temp)
				end
			end

            # ///////////////////////////////////////////
            # run service statuscheck once every 10 turns
            if totalloop_iteration % 10 == 0 
                checkservice
            end

            totalloop_iteration = totalloop_iteration + 1
        end

    end

    def checkservice # runs service --status-all check and greps for string match in SERVICESTATUS_CHECK[]
        len = @SERVICESTATUS_CHECK.length
        counter = 0

        command = "sudo service --status-all | grep -e #{@SERVICESTATUS_CHECK[counter]}"
        while counter < len
            command = command + " -e #{@SERVICESTATUS_CHECK[counter]}"
            counter = counter + 1
        end

        counter = 0
        output = `#{command}`.split("\n") # execute
        while counter < len
            if output[counter].include? "-"

                alert_message = "WATCHTOWER: servicecheck #{output[counter]} -> restarting"
                system("sudo service #{@SERVICESTATUS_CHECK[counter]} start")

                if @silent_mode == false
                    print "\n"
                    print alert_message
                end
                form = "notify-send WATCHTOWER \"ALLERT: #{alert_message} !!\""
                system form
                form = "echo \"[#{alert_message.rstrip}]\" >> /home/#{@user.rstrip}/#{@main_logfile}"
                system form
                form = "echo \"[#{`date`.rstrip}] - #{alert_message.rstrip}\" >> /home/#{@user.rstrip}/#{@event_logfile}"
                system form

            else
                print "\n WATCHTOWER: servicecheck #{output[counter]}"
            end
            counter = counter + 1
        end
    end

    def preliminary_operation
        if @silent_mode == false
            system("clear")
            heading_function("#{@scriptname} - File Verification")
            print "\n Current working directory = #{@cwd}"
            print "\n Criticle file verification:\n"

            sleep 0.1
            counter = 0
            while counter < @LOGFILE_STORE.length
                file = @LOGFILE_STORE[counter]

                print "\n"
                print output_format(" - checking file [#{file}]",50," ")

                verdict = filepresence_check(file)
                sleep @looplatency_cap
                if verdict == 1
                    print "PRESENCE CONFIRMED"
                else
                    print "FILE NOT FOUND"
                end

                counter = counter + 1
            end

        else
        end
        standard_operation
    end

    # ====================================================================================================================

    preliminary_operation

end

Process.detach(primary)