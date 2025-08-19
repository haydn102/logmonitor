#==================================================================================
#                                                                                ==
#                                                           ##    ## ######      ==
#    WATCHTOWER MK3                                         ##    ## ##   ##     ==
#                                                           ##    ## ##    ##    ==
#    Haydn Dungey (c) - 18-8-25                             ##    ## ##    ##    ==
#     - EXPLANATION: program scans relevant OS logs and     ######## ##    ##    ==
#       command output for specified string match           ##    ## ##    ##    ==
#    Built for Linux                                        ##    ## ##    ##    ==
#     - Last Mod - 17/8/25                                  ##    ## ##   ##     ==
#                                                           ##    ## ######      ==
#                                                                                ==
# =================================================================================

# make sure watchtower_rules.yaml is in same working directory:
#
# Rules:
#   - name: New Terminal Session
#     logfile: /var/log/auth.log
#     windowallert: False
#     loghit_text: "New Session"
#     alert_message: "New Terminal session DETECTED"
#     loghit_exception: null

require 'yaml'
require 'logger'

# Define the Struct
Alertrule = Struct.new(:name, :logfile, :windowallert, :loghit_text, :linecount, :hitcount, :alert_message, :loghit_exception)

@RULE_CONFFILE      = "watchtower_rules.yaml"
@LOGFILE_EVENT      = "/home/haydn/watchlogs/WATCHTOWER_eventlog.txt"
@LOGFILE_VERBOSE    = "/home/haydn/watchlogs/WATCHTOWER_verboselog.txt"
@LOGFILE_STATUS     = "/home/haydn/watchlogs/WATCHTOWER_statuslog.txt"

# Define a shared formatter
event_formatter = proc do |severity, datetime, progname, msg|
    formatted_time = datetime.strftime('%Y-%m-%d %H:%M:%S')
    "[#{formatted_time}] #{severity} -- #{msg}\n"
end

LOG = { # Create loggers with custom formatter
    event:   Logger.new("#{@LOGFILE_EVENT}"),
    verbose: Logger.new("#{@LOGFILE_VERBOSE}"),
    status:  Logger.new("#{@LOGFILE_STATUS}")
}

LOG[:event].formatter = event_formatter
LOG[:event].info("Initiating startup")

@scriptname = $0

@sleep_increment = 2    # pause time between search loops
@master_width = 105     # cmd UI display width
@looplatency_cap = 0.02 # sleep time between multiple-operations to cater for discrepancy
@errorStore = []        # storing sys report details for postumous display
@SEARCH_ARRAY = []      # contains static data on all search items (manually added below)
@FileSTRUCT_array = []  # contains iteratively updated details on all files (manually added below)

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

# conduct stringmatch at limited file depth
# - returns false if no match, or array of log hit lines
def logparse_protocol(log,parsedepth,string,exceptions)
    returnarray = []

    print "\nSEARCHING: #{log} at depth #{parsedepth}"

    command = "tail -#{parsedepth} #{log} | grep '#{string}'"
    syntax_check = `#{command}`.split("\n")
    print"\n"
    puts syntax_check

    if syntax_check.length > 0
        for line in syntax_check do
            if line.include? string
                returnarray = returnarray.push(line)
            end
        end
    end

    if returnarray.length == 0
        return false
    else
        return returnarray
    end
end

# handles alerting, logging
def alert_protocol(rulename,alert_message,alert_window,results)
    for line in results do

        print " - DETECTED HIT [#{rulename}]"
        LOG[:event].warn("#{rulename}")
        LOG[:verbose].warn("#{line}")

        # alert notification
        form = "notify-send WATCHTOWER 'ALERT: #{alert_message} !!'"
        system form

        if alert_window == true

        end
    end
end

# ////////////////////////////////////////////////////////////////////////////////////////////////


def standard_op(rules)
 
    master_iteration = 0
    while true

        subcounter = 0
        while subcounter < @SEARCH_ARRAY.length
            rule_item           = @SEARCH_ARRAY[subcounter]
            logfile             = rule_item.logfile
            rulename            = rule_item.name
            hitstring           = rule_item.loghit_text
            currenthit          = rule_item.hitcount
            currentlinecount    = rule_item.linecount
            alert_message       = rule_item.alert_message
            alert_window        = rule_item.windowallert
            exceptions          = rule_item.loghit_exception

            newlinecount = (`wc -l #{logfile}`).to_i # get new linecount
            difference = newlinecount - currentlinecount
            if difference > 0 # new lines to scan condition

                results = logparse_protocol(logfile,difference,hitstring,exceptions)
                if results != false
                    alert_protocol(rulename,alert_message,alert_window,results)
                end

                @SEARCH_ARRAY[subcounter].linecount = newlinecount # set new linecount
            end

            subcounter += 1
        end

        sleep @sleep_increment
        master_iteration += 1
    end
end


def init
    require 'yaml'

    # Define the Struct
    # Load YAML file
    config = YAML.load_file(@RULE_CONFFILE)  # Adjust path as needed

    # Parse rules into Structs
    rules = config["Rules"].map do |rule_hash|
    Alertrule.new(
        rule_hash["name"],
        rule_hash["logfile"],
        rule_hash["windowallert"],
        rule_hash["loghit_text"],
        0,
        rule_hash["alert_message"],
        rule_hash["loghit_exception"]
    )
    end

    # Use it (example)
    rules.each do |rule|
        sleep @looplatency_cap

        print output_format("\n - checking file [#{rule.logfile}]",50," ") # filecheck
        verdict = filepresence_check(rule.logfile)
        if verdict == 1
            print " - FOUND"
        else
            print " - FILE NOT FOUND !!! skipping rule"
            next # skip if no log file
        end
        
        linecount = (`wc -l #{rule.logfile}`).to_i # init linecount
        @SEARCH_ARRAY.push(Alertrule.new(rule.name,rule.logfile,rule.windowallert,rule.loghit_text,linecount,0,rule.alert_message,rule.loghit_exception))
    end

    print "\n\n"
    puts(@SEARCH_ARRAY)
    print "\n"

    standard_op(@SEARCH_ARRAY)

end

init
