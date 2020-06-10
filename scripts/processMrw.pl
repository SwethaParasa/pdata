#!/usr/bin/env perl
# SPDX-License-Identifier: Apache-2.0

################################################################################
# Libraries included
################################################################################
use strict;
use XML::Simple;
use Data::Dumper;
use Targets;
use Math::BigInt;
use Getopt::Long;
use File::Basename;
use feature "state";
use Carp qw( croak confess );
use List::Util qw(max);


################################################################################
# Define some global constants/variables
################################################################################
our %hwsvmrw_plugins;

# Global constants
use constant
{
    # Define a true and false keyword
    true        => 1,
    false       => 0,

    HZ_PER_KHZ  => 1000,
    NUM_PROCS_PER_GROUP  => 4,
};


# The target type's parent pervasive offset value.  Please use wrapper methods
# existsParentPervasiveOffset and getParentPervasiveOffset to access the data
# within this hash. Using the mentioned methods will help with the stability of
# code.
# This value has an effect on attributes PARENT_PERVASIVE and CHIPLET_ID.
my %PARENT_PERVASIVE_OFFSET =
(
    EQ    => 32,
    FC    => 32,
    CORE  => 32,
    MC    => 12,
    MI    => 12,
    MCC   => 12,
    OMI   => 12,
    OMIC  => 12,
    PAUC  => 16,
    IOHS  => 24,
    PAU   => 16,

    NMMU  => 2,
    PEC   => 8,
    PHB   => 8,
);

# The maximum number of target instances per parent.  Please use wrapper methods
# existsMaxInstPerParent and getMaxInstPerParent to access the data within this
# hash.  Using the mentioned methods will help with the stability of code.
# If a child to parent relationship changes for a target type, then
# %MAX_INST_PER_PROC, found below, will need to be updated to reflect change.
# This value has an effect on attributes REL_POS, AFFINITY_PATH and PHYS_PATH.
my %MAX_INST_PER_PARENT =
(
    PROC      => 8, # Number of PROCs per NODE
    EQ        => 8, # Number of EQs per PROC
    FC        => 2, # Number of FCs per EQ
    CORE      => 2, # Number of COREs per FC

    MC        => 4, # Number of MCs per PROC
    MI        => 1, # Number of MIs per MC
    MCC       => 2, # Number of MCCs per MI
    OMI       => 2, # Number of OMIs per MCC/OMIC (has two parents 'a nuclear family')
    OCMB_CHIP => 1, # Number of OCMB_CHIPs per OMI
    PMIC      => 2, # Number of PMICs per DIMM/logical OCMB
    MEM_PORT  => 1, # Number of MEM_PORTs per OCMB
    DIMM      => 1, # Number of DIMMs per MEM_PORT

    OMIC      => 2, # Number of OMICs per MC

    PAUC      => 4, # Number of PAUCs per PROC
    IOHS      => 2, # Number of IOHSs per PAUC
    PAU       => 1, # Number of PAUs per IOHS

    NMMU      => 2, # Number of NMMUs per PROC
    OCC       => 1, # Number of OCCs per PROC
    NX        => 1, # Number of NCs per PROC
    PEC       => 2, # Number of PECs per PROC
    PHB       => 3, # Number of PHBs per PEC
    SEEPROM   => 1, # Default to 1 for now
    SBE       => 1, # Default to 1 for now
    TPM       => 1, # Default to 1 for now
    OSCREFCLK => 1, # Default to 1 for now
    PERV      => 56, # Number of PERVs per PROC
                     # Only 39 used, but they are sparsely populated
    PCICLKENDPT => 1, # Number of PCICLKENDPTs per PROC
    LPCREFCLKENDPT => 1, # Number of LPCREFCLKENDPTs per PROC
    OMIC_CLK => 1, # Number of OMIC_CLK per PROC
    CAPP => 2, # Number of CAPP per PROC
);

# The maximum number of target instances per PROC.  Please use wrapper methods
# existsMaxInstPerProc and getMaxInstPerProc to access the data within this
# hash.  Using the mentioned methods will help with the stability of code.
# These values are calculated/controlled from the %MAX_INST_PER_PARENT values.
# This value has an effect on attributes HUID, ORDINAL_ID and FAPI_POS.
my %MAX_INST_PER_PROC =
(
    EQ         => getMaxInstPerParent("EQ"),
    FC         => getMaxInstPerParent("EQ") * getMaxInstPerParent("FC"),
    CORE       => getMaxInstPerParent("EQ") * getMaxInstPerParent("FC") *
                  getMaxInstPerParent("CORE"),

    MC         => getMaxInstPerParent("MC"),
    MI         => getMaxInstPerParent("MC") * getMaxInstPerParent("MI"),
    MCC        => getMaxInstPerParent("MC") * getMaxInstPerParent("MI") *
                  getMaxInstPerParent("MCC"),
    OMI        => getMaxInstPerParent("MC") * getMaxInstPerParent("MI") *
                  getMaxInstPerParent("MCC") * getMaxInstPerParent("OMI"),
    OCMB_CHIP  => getMaxInstPerParent("MC") * getMaxInstPerParent("MI") *
                  getMaxInstPerParent("MCC") * getMaxInstPerParent("OMI") *
                  getMaxInstPerParent("OCMB_CHIP"),
    MEM_PORT   => getMaxInstPerParent("MC") * getMaxInstPerParent("MI") *
                  getMaxInstPerParent("MCC") * getMaxInstPerParent("OMI") *
                  getMaxInstPerParent("OCMB_CHIP") * getMaxInstPerParent("MEM_PORT"),
    DDIMM      => getMaxInstPerParent("MC") * getMaxInstPerParent("MI") *
                  getMaxInstPerParent("MCC") * getMaxInstPerParent("OMI") *
                  getMaxInstPerParent("OCMB_CHIP") * getMaxInstPerParent("MEM_PORT") *
                  getMaxInstPerParent("DIMM"),
    PMIC       => getMaxInstPerParent("MC") * getMaxInstPerParent("MI") *
                  getMaxInstPerParent("MCC") * getMaxInstPerParent("OMI") *
                  getMaxInstPerParent("OCMB_CHIP") * getMaxInstPerParent("PMIC"),

    OMIC       => getMaxInstPerParent("MC") * getMaxInstPerParent("OMIC"),

    PAUC       => getMaxInstPerParent("PAUC"),
    IOHS       => getMaxInstPerParent("PAUC") * getMaxInstPerParent("IOHS"),
    PAU        => getMaxInstPerParent("PAUC") * getMaxInstPerParent("IOHS") *
                  getMaxInstPerParent("PAU"),
                  # For PAU, only 6 used, PAU1 and PAU2 not used

    NMMU       => getMaxInstPerParent("NMMU"),
    OCC        => getMaxInstPerParent("OCC"),
    NX         => getMaxInstPerParent("NX"),
    PEC        => getMaxInstPerParent("PEC"),
                  # PEC is same as PBCQ
    SEEPROM    => getMaxInstPerParent("SEEPROM"),
    OSCREFCLK  => getMaxInstPerParent("OSCREFCLK"),
    PHB        => getMaxInstPerParent("PEC") * getMaxInstPerParent("PHB"),
                  # PHB is same as PCIE
    PERV       => getMaxInstPerParent("PERV"),

    PCIESWITCH => 2,
    MBA        => 16,
    PPE        => 51, # Only 21, but they are sparsely populated
    SBE        => 1,
    TPM        => 1,
    SMPGROUP   => 8,
    PCICLKENDPT => getMaxInstPerParent("PCICLKENDPT"),
    LPCREFCLKENDPT => getMaxInstPerParent("LPCREFCLKENDPT"),
    OMIC_CLK => getMaxInstPerParent("OMIC_CLK"),
    CAPP => getMaxInstPerParent("CAPP"),
);


################################################################################
# Usage statement
################################################################################
sub printUsage
{
    print "
processMrwl.pl -x [XML filename] [OPTIONS]
Options:
        -build <hb | fsp | bmc> = hb  - process HB targets only (the default)
                                  fsp - process FSP targets in addition to HB targets
                                  bmc - process BMC targets in addition to HB targets
        -c <2N | w> = special configurations we want to run
                      2N - special 2 node config with extra ABUS links
                      w - Special MST wrap config
        -d = run in debug mode
        -f = force output file creation even when errors
        -fh = print the full hierarchy of the XML file
        -hh = print the hierarchy, only HB is interested in, from the XML file
        -o <filename> = output filename
        -r = create report and save to [system_name].rpt
        -s = run in silent mode, suppress warnings but not errors,
             use judiciously
        -t = run self test
";
    exit(1);
} # end sub printUsage


################################################################################
# Main - The starting point for this script
################################################################################
main();
exit 0;  # YOU SHALL NOT PASS!! All code should start in sub main

#--------------------------------------------------
# @brief main
#
# @details The real starting point of this script.
#--------------------------------------------------
sub main
{
    # Create a Target object
    my $targetObj = Targets->new;

    # Extract the caller's options off the command line and validate.
    # Will exit if options are not valid.
    getAndValidateCallerInputOptions($targetObj);

    # Run tests if asked to do so
    if ($targetObj->{run_internal_tests} == 1)
    {
        runTests($targetObj);
        return 0;
    }

    # Print HB target hierarchy only, ignore all other options
    if ($targetObj->{print_hb_hierarchy} == 1)
    {
        my $xmlFile = $targetObj->{serverwiz_file};
        print "\nPrinting out the HB target hierarchy from XML file $xmlFile.\n";
        print "All other options ignored and no processing of file done.\n";
        print "I suggest piping this out to a file for posterity.\n\n";
        printHostbootTargetHierarchy($targetObj, $xmlFile);
        return 0;
    }
    # Print the full target hierarchy, ignore all other options
    elsif ($targetObj->{print_full_hierarchy} == 1)
    {
        my $xmlFile = $targetObj->{serverwiz_file};
        print "\nPrinting out the Full target hierarchy from XML file $xmlFile.\n";
        print "All other options ignored and no processing of file done.\n";
        print "I suggest piping this out to a file for posterity.\n\n";
        $targetObj->printFullTargetHierarchy($xmlFile);
        return 0;
    }

    ## If not testing and not printing out hierarchy, then let's get to work ...
    # Load the XML and process the file, extracting targets and associated
    # attributes, with their data, to the targets.
    loadXmlFile($targetObj);

    # First pass of processing the target hierarchy setting common attributes
    # such as FAPI_NAME, PHYS_PATH, AFFINITY_PATH, ORDINAL_ID, HUID and
    # many others.
    processTargets($targetObj);

    if ($targetObj->{build} eq "fsp")
    {
        eval ("use processMrw_fsp; return 1;");
        processMrw_fsp::return_plugins();
    }

    # Write the report
    writeReport($targetObj);

    # Second pass of processing the target hierarchy attribute data that could
    # could not be determined until after an initial pass.
    postProcessTargets($targetObj);

    if ($targetObj->{build} eq "fsp")
    {
        processMrw_fsp::loadFSP($targetObj);
    }

    # Once ALL processing of the targets has been completed, remove
    # deprecated and un-needed attributes from targets
    pruneTargetAttributes($targetObj);

    # Check for errors in the targets
    errorCheckTheTargets($targetObj);

    # Write the results of processing the targets to an XML file
    writeResultsToXml($targetObj);
}


################################################################################
# Subroutines called from the main, except test and print
# routines which are located at end of file.
################################################################################
#--------------------------------------------------
# @brief Extract caller's command line options
#
# @details Extract caller's command line options and
#          validate them.  If valid then store in the
#          global Target object for easy retrieval.
#          If options are not valid, then print
#          usage statement and exit script.
#
# @param [in] $targetObj - The global target object.
#--------------------------------------------------
sub getAndValidateCallerInputOptions
{
    my $targetObj = shift;

    # Local variables, and their defaults, to cache the command line options to
    my $serverwiz_file  = "";
    my $build           = "hb";  # Used to process HB targets only or FSP and HB
                                 # targets.  Process HB targets is the default.
                                 # It is also used as a tag for the generated
                                 # output file, if no output file given.
    my $system_config   = "";
    my $debug           = 0;
    my $print_full_hierarchy = 0; # print the full XML hierarchy
    my $print_hb_hierarchy   = 0; # print only the  XML hierarchy
    my $force           = 0;
    my $output_file     = "";
    my $report          = 0;
    my $stealth_mode    = 0;  # Only print errors not warnings
    my $run_internal_tests   = 0;
    my $version         = 0;

    # Grab the user's command line options.  If an option is not recognized,
    # print usage statement and exit script.
    GetOptions(
        "x=s" => \$serverwiz_file, # string (mandatory)
        # The following options are optional
        "build=s" => \$build,      # string
        "c=s" => \$system_config,  # string
        "d"   => \$debug,          # flag
        "fh"  => \$print_full_hierarchy,  # flag
        "hh"  => \$print_hb_hierarchy,    # flag
        "f"   => \$force,          # numeric
        "o=s" => \$output_file,    # string
        "r"   => \$report,         # flag
        "s"   => \$stealth_mode,   # flag
        "t"   => \$run_internal_tests,  # flag
      )
      or printUsage();

    # If caller did not specify an input file, then print usage and exit
    if ($serverwiz_file eq "")
    {
        printUsage();
    }

    # If caller used an invalid option for 'system_config' then state so and exit
    if ( ($system_config ne "")     &&
         ($system_config ne "2N")   &&
         ($system_config ne "w")  )

    {
        print "\nInvalid input \"$system_config\" for option -c\n";
        printUsage();
    }

    # If caller used an invalid option for 'build' then state so and exit
    if ( ($build ne "")     &&
         ($build ne "hb")   &&
         ($build ne "fsp")  &&
         ($build ne "bmc")
       )

    {
        print "\nInvalid input \"$build\" for option -build\n";
        printUsage();
    }

    # Save the caller's input options to global storage for easy retrieval
    $targetObj->{serverwiz_file} = $serverwiz_file;
    $targetObj->{serverwiz_dir} = dirname($serverwiz_file);
    $targetObj->{build} = $build;
    $targetObj->{system_config} = $system_config;
    $targetObj->{debug} = $debug;
    $targetObj->{force} = $force;
    $targetObj->{output_file} = $output_file;
    $targetObj->{report} = $report;
    $targetObj->{stealth_mode} = $stealth_mode;
    $targetObj->{run_internal_tests} = $run_internal_tests;
    $targetObj->{print_full_hierarchy} = $print_full_hierarchy;
    $targetObj->{print_hb_hierarchy} = $print_hb_hierarchy;
} # end getAndValidateCallerInputOptions

#--------------------------------------------------
# @brief Loads the MRW XML file
#
# @details Loads the MRW XML file, creates the target instances, applies global
#          settings, stores enumerations, stores groups and builds hierarchy.
#
# @param [in] $targetObj - The global target object.
#--------------------------------------------------
sub loadXmlFile
{
    my $targetObj = shift;

    $XML::Simple::PREFERRED_PARSER = 'XML::Parser';
    $targetObj->loadXML($targetObj->{serverwiz_file});

    # Set the version number to the given input XML file
    $targetObj->setVersion();
} # end loadXmlFile

#--------------------------------------------------
# @brief Iterate thru target hierarchy and set attributes
#
# @details Iterate thru target hierarchy and set attributes, the expected
#          hierarchy: sys/node/proc/<unit>.
#          The common attributes that are set: FAPI_NAME, PHYS_PATH,
#          AFFINITY_PATH, ORDINAL_ID, HUID and others.
#
# @note If you add another process method, do not forget to update the
#       array 'processTargetControl' to call the new method.
#
# @param [in] $targetObj - The global target object.
#--------------------------------------------------
sub processTargets
{
    my $targetObj = shift;

    # Process the targets in a breadth first fashion, allowing the children
    # targets to take advantage of the processed parents.
    #
    # Although the targets DIMM, BMC, etc. are not at the same hierarchical
    # level, the important thing is that their parents get processed first.
    #
    # Excluding the SYS target, which is the starting point, the targets in
    # this list are targets that are not easily accessible from the SYS target,
    # the NODE target or as a child from the given targets. Example, the PROC
    # is not directly accessible from the SYS target or it's child, the NODE
    # target. The same is true for the DIMM, BMC, POWER_SEQUENCER and TPM
    my @processTargetControl = qw (SYS PROC DIMM BMC POWER_SEQUENCER TPM);
    foreach my $targetTypeControl (@processTargetControl)
    {
        foreach my $target (sort keys %{ $targetObj->getAllTargets() })
        {
            my $type = $targetObj->getType($target);

            # If this is not the next target to work on, then skip it
            if ($type ne $targetTypeControl)
            {
                next;
            }

            if ($type eq "SYS")
            {
                # This call will not only process the SYS target but also it's
                # child, the NODE target.
                processSystem($targetObj, $target);
            }
            elsif ($type eq "PROC")
            {
                # The P10 children that get processed are:
                #     CORE, EQ, FC, IOHS, MC, MCC, MI, NMMU, NX, OCC, OMI,
                #     OMIC, OSCREFCLK, PAU, PAUC, PEC, PERV, SEEPROM
                processProcessorAndChildren($targetObj, $target);
            }
            elsif ( ($type eq "DIMM")   &&
                    ($targetObj->getTargetType($target) eq "lcard-dimm-ddimm") )
            {
                # The P10 children that get processed are PMIC, OCMB, MEM_PORT
                processDdimmAndChildren($targetObj, $target);
            }
            elsif ($type eq "BMC")
            {
                processBmc($targetObj, $target);
            }
            elsif ($type eq "POWER_SEQUENCER")
            {
                # Strip off the chip- part of the target type name
                $type =~ s/chip\-//g;

                # Currently only UCD9090 and UCD90120A on FSP systems are supported.
                # Skip over all other UCD types.
                if (($type ne "UCD9090") && ($type ne "UCD90120A"))
                {
                    next;
                }

                processUcd($targetObj, $target);
            }
            # NOTE that this is a place holder for processing TPM.  Currently
            # type will not match 'TPM', will need to update to get a match.
            elsif ($type eq "TPM")
            {
                processTpm($targetObj, $target);
            }
        } # end foreach my $target (sort keys %{ $targetObj->{data}->{TARGETS} })
    } # end foreach my $targetTypeControl (@processTargetControl)
} # end processTargets

#--------------------------------------------------
# @brief Loop through all targets and set attributes that have yet to be set
#
# @param [in] $targetObj - The global target object.
#--------------------------------------------------
sub postProcessTargets
{
    my $targetObj = shift;

    # This 2nd round of processing should not need to be done in any order.
    # Should be able to process targets as they are encountered.
    foreach my $target (sort keys %{ $targetObj->getAllTargets() })
    {
        my $type = $targetObj->getType($target);

        if ($type eq "SYS")
        {
            postProcessSystem($targetObj, $target);
        }
        elsif ($type eq "PROC")
        {
            postProcessProcessor($targetObj, $target);

            if ($targetObj->{build} eq "fsp")
            {
                do_plugin("fsp_proc", $targetObj, $target);
            }
        }
        elsif ($type eq "OMI")
        {
            # Only want OMIs which have an MC parent.
            if ($targetObj->findParentByType($target, "MC", false) ne "")
            {
                postProcessOmi($targetObj, $target);
            }
        }
        elsif ($type eq "OMIC")
        {
            postProcessOmic($targetObj, $target);
        }
        elsif ($type eq "APSS")
        {
            postProcessApss($targetObj, $target);
        }
        elsif ($type eq "POWER_SEQUENCER")
        {
            my $target_type = $targetObj->getTargetType($target);

            # Strip off the chip- part of the target type name
            $target_type =~ s/chip\-//g;

            # Currently only UCD9090 and UCD90120A on FSP systems are supported.
            # All other UCD types are skipped.
            if (($target_type eq "UCD9090")
                || ($target_type eq "UCD90120A"))
            {
                postProcessUcd($targetObj, $target);
            }
        }
        # NOTE that this is a place holder for processing TPM.  Currently
        # type will not match 'TPM', will need to update to get a match.
        elsif ($type eq "TPM")
        {
            postProcessTpm($targetObj, $target);
        }
        elsif ($type eq "IOHS")
        {
            postProcessIohs($targetObj, $target);
        }

        postProcessIpmiSensors($targetObj, $target);
    } # end foreach my $target (@targets)
} # end postProcessTargets

#--------------------------------------------------
# @brief Remove attributes associated with target.
#        Either because they have been deprecated
#        or simply not used/needed.
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target - The target to remove attributes from
# @param[in] $type -   The type of the target
#
# TODO RTC: 178351 Remove depricated Attribute from HB XML
# these are obsolete
#--------------------------------------------------
sub pruneTargetAttributes
{
    my $targetObj = shift;

    foreach my $target (sort keys %{ $targetObj->getAllTargets() })
    {
        my $type = $targetObj->getType($target);
        if ($type eq "SYS")
        {
            $targetObj->deleteAttribute($target,"XSCOM_BASE_ADDRESS");
        }
        elsif ($type eq "MEM_PORT")
        {
            $targetObj->deleteAttribute($target,
                               "EXP_SAFEMODE_MEM_THROTTLED_N_COMMANDS_PER_PORT");
        }
        elsif ($type eq "PHB")
        {
            $targetObj->deleteAttribute($target,"DEVICE_ID");
            $targetObj->deleteAttribute($target,"HDDW_ORDER");
            $targetObj->deleteAttribute($target,"MAX_POWER");
            $targetObj->deleteAttribute($target,"MGC_LOAD_SOURCE");
            $targetObj->deleteAttribute($target,"PCIE_32BIT_DMA_SIZE");
            $targetObj->deleteAttribute($target,"PCIE_32BIT_MMIO_SIZE");
            $targetObj->deleteAttribute($target,"PCIE_64BIT_DMA_SIZE");
            $targetObj->deleteAttribute($target,"PCIE_64BIT_MMIO_SIZE");
            $targetObj->deleteAttribute($target,"PCIE_CAPABILITES");
            $targetObj->deleteAttribute($target,"SLOT_INDEX");
            $targetObj->deleteAttribute($target,"SLOT_NAME");
            $targetObj->deleteAttribute($target,"VENDOR_ID");
        }

        # Remove our book keeping
        $targetObj->deleteAttribute($target,"HB_TARGET_PROCESSED");
    }
} # end pruneTargetAttributes

#--------------------------------------------------
# @brief Write report
#
# @param [in] $targetObj - The global target object.
#--------------------------------------------------
sub writeReport
{
    my $targetObj = shift;

    my $str=sprintf(
        " %30s | %10s | %6s | %4s | %9s | %4s | %4s | %4s | %10s | %s\n",
        "Sensor Name","FRU Name","Ent ID","Type","Evt Type","ID","Inst","FRU",
        "HUID","Target");

    $targetObj->writeReport($str);
    my $str=sprintf(
        " %30s | %10s | %6s | %4s | %9s | %4s | %4s | %4s | %10s | %s\n",
        "------------------------------","----------",
        "------","----","---------","----","----","----","----------",
        "----------");

    $targetObj->writeReport($str);
} # end writeReport

#--------------------------------------------------
# @brief Check the processed targets for errors
#
# @param [in] $targetObj - The global target object.
#--------------------------------------------------
sub errorCheckTheTargets
{
    my $targetObj = shift;

    # Check topology
    foreach my $n (keys %{$targetObj->{TOPOLOGY}})
    {
        if ($targetObj->{TOPOLOGY}->{$n} > 1)
        {
            print "ERROR: Fabric topology invalid. $targetObj->{TOPOLOGY}->{$n}"
                  ." targets have same FABRIC_TOPOLOGY_ID ($n)\n";
            $targetObj->myExit(3);
        }
    }

    # Check for errors
    foreach my $target (keys %{ $targetObj->getAllTargets() })
    {
# TODO, RTC 215164. Having issues with power10-0 so wrapped errorCheck with if statement:
# ERROR: EEPROM_VPD_PRIMARY_INFO/devAddr attribute is invalid (Target=/sys-0/node-0/nisqually-0/proc_socket-0/godel-0/power10-0)
#	I2C connection to target is not defined
# So I wrapped the errorCHeck with the if statement. Once SPI comes online,
# then the if statement can be removed.
        if ($target != "/sys-0/node-0/nisqually-0/proc_socket-0/godel-0/power10-0")
        {
            errorCheck($targetObj, $target);
        }
    }
} # end sub errorCheckTheTargets

# @function getStaticAbsLocationCode
#
# @brief Returns the static portion of the absolution location code for a given
#     target.  The returned location code does -not- reflect the chassis
#     location code prefix (including dash), but otherwise includes all other
#     components of the final location code.  It will be up to the firmware to
#     dynamically add the chassis location code prefix to form a complete
#     location code.
#
#     For example, if chip 0's full location code is: U78DA.ND1.1234567-P0-C0,
#     this API will return it as P0-C0.
#
# @param[in] $i_targetObj Global target object (required)
# @param[in] $i_target    The target to compute static portion of the absolute
#     location code for (required)
#
# @return The static portion of the absolute location code for the target, empty
#     on error.
sub getStaticAbsLocationCode
{
    my $i_targetObj = shift;
    my $i_target = shift;
    my $tempTarget = $i_target;

    my @locationCodeArray = ();
    my $arrayIndex = 0;
    my $locationCode = '';
    my $locationCodeType = '';
    my $tempLocationCode = '';

    if($i_targetObj->getTargetParent($tempTarget) ne '')
    {
        my $done = 0;
        do
        {
            if(!defined $tempTarget)
            {
                $done = 1;
            }
            else
            {
                if(!$i_targetObj->isBadAttribute($tempTarget, "LOCATION_CODE"))
                {
                    $tempLocationCode = $i_targetObj->getAttribute($tempTarget,
                        "LOCATION_CODE");
                }
                else
                {
                    $tempLocationCode = '';
                }

                if(!$i_targetObj->isBadAttribute($tempTarget,
                        "LOCATION_CODE_TYPE"))
                {
                    $locationCodeType = $i_targetObj->getAttribute($tempTarget,
                        "LOCATION_CODE_TYPE");
                }
                else
                {
                    $locationCodeType = '';
                }

                if($locationCodeType eq '' || $locationCodeType eq 'ASSEMBLY' ||
                    $tempLocationCode eq '')
                {
                    $tempTarget = $i_targetObj->getTargetParent($tempTarget);
                }
                elsif($locationCodeType eq 'RELATIVE')
                {
                    $locationCodeArray[$arrayIndex++] = $tempLocationCode;
                    $tempTarget = $i_targetObj->getTargetParent($tempTarget);
                }
                elsif($locationCodeType eq 'ABSOLUTE')
                {
                    $locationCodeArray[$arrayIndex++] = $tempLocationCode;
                    $done = 1;
                }
            }

        } while(!$done);
    }

    my $dash='';
    for(my $i = $arrayIndex; $i > 0; $i--)
    {
        $locationCode = $locationCode.$dash.$locationCodeArray[$i-1];
        $dash="-";
    }

    return $locationCode;
}

#--------------------------------------------------
# @brief Write out the results to an XML file
#
# @note Blank attributes are skipped and not printed out within this method
#       call chain: Targets.pm::printXML -> Targets.pm::printTarget
#                   -> Targets.pm::printAttribute
#
# @param [in] $targetObj - The global target object.
#--------------------------------------------------
sub writeResultsToXml
{
    my $targetObj = shift;

    my $xml_fh;
    my $filename;
    my $config_str = $targetObj->{system_config};

    #If user did not specify the output filename, then build one up by using
    #config and build parameters
    if ($targetObj->{output_file} eq "")
    {
        if ($config_str ne "")
        {
            $config_str = "_" . $config_str;
        }

        $filename = $targetObj->{serverwiz_dir} . "/" . $targetObj->getSystemName() . $config_str . "_" . $targetObj->{build} . ".mrw.xml";
    }
    else
    {
        $filename = $targetObj->{output_file};
    }

    print "Creating XML:    $filename\n";
    select()->flush(); # flush buffer before spewing out error message
    open($xml_fh, ">$filename") || die "Unable to create: $filename";

    $targetObj->printXML($xml_fh, "top", $targetObj->{build});
    close $xml_fh;
    if (!$targetObj->{errorsExist})
    {
        ## optionally print out report
        if ($targetObj->{report})
        {
            print "Writing report to: ".$targetObj->{report_filename}."\n";
            $targetObj->writeReportFile();
        }
        print "MRW created successfully!\n";
    }
} # end sub writeResultsToXml


################################################################################
# Processing subroutines
################################################################################
#--------------------------------------------------
# @brief Process targets of type SYS
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The SYS target
#--------------------------------------------------
sub processSystem
{
    my $targetObj = shift;
    my $target    = shift;

    my $type      = targetTypeSanityCheck($targetObj, $target, "SYS");

    # Getting the system position from the system target is unreliable because
    # some MRWs have invalid (negative) values. Instead, use a static variable
    # to keep track of the number of systems in the mrw.
    state $sysPos = -1;
    # Setting the position to -1 and then incrementing it to 0 right away
    # ensures that the variable is initialized to a valid starting value and
    # that as more are processed the value is updated correctly before it's used
    #
    # The other reason to do it here as opposed to on exit allows us to keep the
    # logic together to avoid coding mistakes in the future.
    $sysPos++;

    my $fapiName  = $targetObj->getFapiName($type);

    # SYS target has PHYS_PATH and AFFINITY_PATH defined in the XML
    # Also, there is no HUID for SYS
    $targetObj->setAttribute($target,"ORDINAL_ID", $sysPos);
    $targetObj->setAttribute($target,"FAPI_POS",   $sysPos);
    $targetObj->setAttribute($target,"FAPI_NAME",  $fapiName);


    # Save this target for retrieval later when printing the xml (sub printXML)
    $targetObj->{targeting}{SYS}[$sysPos]{KEY} = $target;

    # Mark this target as processed
    markTargetAsProcessed($targetObj, $target);

    ## Process NODE children. Children may differ for different systems.
    # Sanity check flag, to make sure that this code is still valid.
    my $foundNode = false;

    # If an error, such as 'Can't use string ("") as an ARRAY', then the
    # structure of the MRW has changed and this script needs updating.
    foreach my $child (@{ $targetObj->getTargetChildren($target) })
    {
        my $childType = $targetObj->getType($child);
        if ($childType eq "NODE")
        {
            processNode($targetObj, $child);
            $foundNode = true;
        }
    }

    if ($foundNode == false)
    {
        select()->flush(); # flush buffer before spewing out error message
        die "\nprocessSystem::ERROR: Did not find a \"NODE\" " .
            "child for the SYS ($target). Did the MRW structure " .
            "change?  If so update this script to reflect changes.  Error"
    }
} # end sub processSystem

#--------------------------------------------------
# @brief Process targets of type NODE
#
# @pre SYS targets need to be processed beforehand
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The NODE target
#--------------------------------------------------
sub processNode
{
    my $targetObj = shift;
    my $target    = shift;

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target's parent has been processed.
    my $type = targetTypeSanityCheck($targetObj, $target, "NODE");
    validateParentHasBeenProcessed($targetObj, $target);

    # Get some useful info from the NODE parent's SYS targets
    my $sysParent = $targetObj->findParentByType($target, "SYS");
    my $sysParentPos = $targetObj->getAttribute($sysParent, "ORDINAL_ID");
    my $sysParentAffinity = $targetObj->getAttribute($sysParent, "AFFINITY_PATH");
    my $sysParentPhysical = $targetObj->getAttribute($sysParent, "PHYS_PATH");

    # Hostboot does not model the backplane, just the node that holds the
    # backplane, so compute the backplane's location code and set that value
    # on the node target, then clear out the value on the backplane level.
    foreach my $child (@{$targetObj->getTargetChildren($target)})
    {
        my $childTargetType = $targetObj->getTargetType($child);
        if ($childTargetType eq "card-motherboard")
        {
            my $staticAbsLocationCode = getStaticAbsLocationCode($targetObj,$child);
            $targetObj->setAttribute($target, "STATIC_ABS_LOCATION_CODE",$staticAbsLocationCode);
            $targetObj->setAttribute($child, "STATIC_ABS_LOCATION_CODE","");
        }
    }

    # For high-end, multi-drawer systems there may be a control node that
    # contains service processor logic but no CEC (processor) logic. Thus,
    # the node count begins at 1 instead of zero and must be adjusted back to
    # a zero based count to have affinity/physical paths remain CEC centric.
    #
    # To do this generically, we use a state (static) variable that will keep a
    # running total of the number of nodes encountered in this mrw instead of
    # the position that was provided to us in the xml.
    state $nodePosPerSystem = -1;
    # Setting the position to -1 and then incrementing it to 0 right away
    # ensures that the variable is initialized to a valid starting value and
    # that as more are processed the value is updated correctly before it's used
    #
    # The other reason to do it here as opposed to on exit allows us to keep the
    # logic together to avoid coding mistakes in the future.
    $nodePosPerSystem++;

    # Get the FAPI_NAME
    my $fapiName = $targetObj->getFapiName($type);

    # Construct the NODE's physical/affinity path with the retrieved info above
    my $nodeAffinity = $sysParentAffinity . "/node-$nodePosPerSystem";
    my $nodePhysical = $sysParentPhysical . "/node-$nodePosPerSystem";

    # Now that we collected all the data we need, set some target attributes
    $targetObj->setHuid($target, $sysParentPos, $nodePosPerSystem);
    $targetObj->setAttribute($target, "ORDINAL_ID",    $nodePosPerSystem);
    $targetObj->setAttribute($target, "FAPI_POS",      $nodePosPerSystem);
    $targetObj->setAttribute($target, "FAPI_NAME",     $fapiName);
    $targetObj->setAttribute($target, "AFFINITY_PATH", $nodeAffinity);
    $targetObj->setAttribute($target, "PHYS_PATH",     $nodePhysical);

    # Save this target for retrieval later when printing the xml (sub printXML)
    $targetObj->{targeting}{SYS}[$sysParentPos]
                {NODES}[$nodePosPerSystem]{KEY} = $target;

    # Mark this target as processed
    markTargetAsProcessed($targetObj, $target);

} # end sub processNode

#--------------------------------------------------
# @brief Process targets of type PROC and all it's children
#
# @pre NODE targets need to be processed beforehand
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The PROC target
#--------------------------------------------------
sub processProcessorAndChildren
{
    my $targetObj = shift;
    my $target    = shift;

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target's parent has been processed.
    my $type = targetTypeSanityCheck($targetObj, $target, "PROC");
    validateParentHasBeenProcessed($targetObj, $target, "NODE");

    # Find the socket connector for this target
    my $socket = $target;
    while ($targetObj->getAttribute($socket,"CLASS") ne "CONNECTOR")
    {
       $socket = $targetObj->getTargetParent($socket);
    }

    # die if socket connector not found
    if ( ($socket eq undef) || ($socket eq "") )
    {
        select()->flush(); # flush buffer before spewing out error message
        die "processProcessorAndChildren: ERROR: Cannot find socket connector " .
            "for $target.\nError";
    }

    my $socketPosition = $targetObj->getAttribute($socket, "POSITION");

    # Get the PROC position. This is its position relative to the proc socket.
    my $procPosPerSocket = $targetObj->getAttribute($target,"POSITION");

    # To determine the processors position relative to the node we need to
    # figure out the number of procs per socket.
    #
    # DCMs (Dual Chip Module) will have 2 procs per socket
    # SCMs (Single Chip Module) will have 1 per socket
    # NOTE: It looks like this state variable is unused but it is setting
    # $targetObj->{NUM_PROCS_PER_NODE} and doing so in a way that will only set
    # it once.
    state $NumberProcsPerSocket = findProcPerSocket($targetObj, $target);

    # Do the following math to get the unique position for a processor per node.
    my $procPosPerNode = calculateProcPositionPerNode($targetObj,
                                                      $socketPosition,
                                                      $procPosPerSocket);

    # Increment the number of PROCs, per NODE, for data gathering
    # @TODO RTC 247183 - This will be wrong for multi-node systems.
    #       The correct count can be found by taking the number of sockets per
    #       node and multipling that by $NumberProcsPerSocket.
    $targetObj->{NUM_PROCS_PER_NODE}++;

    # Get some useful info from the PROC parent's SYS and NODE targets
    my $sysParent = $targetObj->findParentByType($target, "SYS");
    my $sysParentPos = $targetObj->getAttribute($sysParent, "ORDINAL_ID");
    my $nodeParent = $targetObj->findParentByType($target, "NODE");
    my $nodeParentPos = $targetObj->getAttribute($nodeParent, "ORDINAL_ID");
    my $nodeParentAffinity =$targetObj->getAttribute($nodeParent, "AFFINITY_PATH");
    my $nodeParentPhysical = $targetObj->getAttribute($nodeParent, "PHYS_PATH");

    # @TODO Investigate if FABRIC_GROUP_ID and FABRIC_CHIP_ID are still needed
    # Copy the parent socket attributes FABRIC_GROUP_ID and FABRIC_CHIP_ID to
    # the PROC.  Also use those values to calculate the FAPI position (FAPI_POS)
    my $socketFabricGroupId = $targetObj->getAttribute($socket, "FABRIC_GROUP_ID");
    my $socketFabricChipId  = $targetObj->getAttribute($socket, "FABRIC_CHIP_ID");
    $targetObj->setAttribute($target, "FABRIC_GROUP_ID", $socketFabricGroupId);
    $targetObj->setAttribute($target, "FABRIC_CHIP_ID",  $socketFabricChipId);
    my $procFapiPos = ($socketFabricGroupId * NUM_PROCS_PER_GROUP) + $socketFabricChipId;

    # Get the FAPI_NAME by using the data gathered above.
    my $fapiName = $targetObj->getFapiName($type, $nodeParentPos, $procPosPerNode);

    # Take advantage of previous work done on the NODES.  Use the parent NODE's
    # affinity/physical path for our self and append proc to the end.
    my $procAffinity = $nodeParentAffinity . "/proc-" . $procPosPerNode;
    my $procPhysical = $nodeParentPhysical . "/proc-" . $procPosPerNode;

    # Now that we collected all the data we need, set some target attributes
    $targetObj->setHuid($target, $sysParentPos, $nodeParentPos, $procPosPerNode);
    $targetObj->setAttribute($target, "POSITION",      $procPosPerNode);
    $targetObj->setAttribute($target, "ORDINAL_ID",    $procPosPerNode);
    $targetObj->setAttribute($target, "FAPI_POS",      $procFapiPos);
    $targetObj->setAttribute($target, "FAPI_NAME",     $fapiName);
    $targetObj->setAttribute($target, "AFFINITY_PATH", $procAffinity);
    $targetObj->setAttribute($target, "PHYS_PATH",     $procPhysical);

    # Save this target for retrieval later when printing the xml (sub printXML)
    $targetObj->{targeting}{SYS}[$sysParentPos]{NODES}[$nodeParentPos]
                {PROCS}[$procPosPerNode]{KEY} = $target;

    # Set the PROC's master status
    setProcMasterStatus($targetObj, $target);

    # Mark this target as processed
    markTargetAsProcessed($targetObj, $target);

    # Iterate over the children of the PROC and set some attributes for them
    # NOTE: Must send in the target PROC itself, not it's children.
    # Rainier children: CORE, EQ, FC, IOHS, MC, MCC, MI, NMMU, NX, OCC,
    #         OMI, OMIC, OSCREFCLK, PAU, PAUC, PEC, PERV, SEEPROM
    # Children may differ for different systems.
    iterateOverChiplets($targetObj, $target, $sysParentPos,
                        $nodeParentPos, $procPosPerNode);
} # end sub processProcessorAndChildren

#--------------------------------------------------
# @brief Process targets of type DDIMM and it's children PMIC and OCMB
#
# @pre SYS, NODE and PROC targets need to be processed beforehand
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The DIMM target
#--------------------------------------------------
sub processDdimmAndChildren
{
    my $targetObj = shift;
    my $target    = shift;

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target's parent has been processed.
    my $type = targetTypeSanityCheck($targetObj, $target, "DIMM");
    validateParentHasBeenProcessed($targetObj, $target, "NODE");

    # The DDIMMs are behind the DDIMM conectors, a one to one relationship.
    # Get the DDIMM's position from the parent DDIMM connector
    my $dimmPosPerSystem = $targetObj->getAttribute(
                                $targetObj->getTargetParent($target),
                                "POSITION");

    my $ddimmAffinity = "ERR";
    my $ddimmPosPerParent = "ERR";

    # Find connections for target (DIMM) of bus type ("OMI"), ignore
    # connections FROM this target ("") but find connections TO this target(1).
    my $conn = $targetObj->findConnectionsByDirection($target, "OMI", "", 1);
    if ($conn ne "")
    {
        # Find the OMI bus connection to determine target values
        my $procPosRelativeToNode = "ERR";
        my $mc_num   = "ERR";
        my $mi_num   = "ERR";
        my $mcc_num  = "ERR";
        my $omi_num  = "ERR";
        my $ocmb_num = "ERR";
        my $mem_num  = "ERR";

        foreach my $conn (@{$conn->{CONN}})
        {
            my $source = $conn->{SOURCE};
            # Split the source into proc#, mc#, mi#, mcc#, omic#, omi#
            my @targets = split(/\//, $source);
            # Splitting on "/" makes the first array index an empty string,
            # to correct for this we can simply shift off the first element.
            shift @targets;
            # After splitting and the shift:
            # Source example:/sys-#/node-#/nisqually-#/proc_socket-#/godel-#/power10-#/mc#/mi#/mcc#/omic#/omi#
            # Array index     0     1      2           3             4       5         6   7   8    9     10

            # Strip down the target names to just the instance numbers.
            # Due to inconsistent naming and numerical characters being present
            # in some instance names that aren't the instance number this needs
            # to be done in two steps.
            foreach my $target (@targets)
            {
                # This removes all characters before the -
                # ex. power10-1 becomes 1
                $target =~ s/.*-//g;
                # This removes all non-digit characters.
                # ex. omi0 becomes 0
                $target =~ s/\D//g;
            }

            # Index into the targets array, with identification of index data
            use constant PROC_SOCKET_INDEX => 3;
            use constant PROC_INDEX        => 5;
            use constant MC_INDEX          => 6;
            use constant MI_INDEX          => 7;
            use constant MCC_INDEX         => 8;
            use constant OMI_INDEX         => 10;

            # Target breakdown, excerpt from simics_P10.system.xml:
            # Each P10 has 4 MC units
            # =>Each MC unit has 1 MI unit (a total of 4 per chip)
            # ==>Each MI unit has 2 MCC units (a total of 8 per chip)
            # ===>Each MCC unit has 2 OMI Units (A total of 16 per chip)
            # NOTE: OMI Units are special as they have two parents (MCC + OMIC)
            use integer;
            $procPosRelativeToNode =
                calculateProcPositionPerNode($targetObj,
                                             $targets[PROC_SOCKET_INDEX],
                                             $targets[PROC_INDEX]);

            $mc_num = $targets[MC_INDEX] % getMaxInstPerParent("MC");
            $mi_num = $targets[MI_INDEX]   % getMaxInstPerParent("MI");
            $mcc_num = $targets[MCC_INDEX] % getMaxInstPerParent("MCC");
            $omi_num = $targets[OMI_INDEX] % getMaxInstPerParent("OMI");

            # The values for these are 0
            # NOTE: Going on the assumption that 1 OCMB per DDIMM with
            #       1 MEM_PORT and 1 DIMM, but this may not always be case.
            $ocmb_num = 0;
            $mem_num  = 0;
            $ddimmPosPerParent = 0;

            # Update the affinity path with the data gathered above.
            $ddimmAffinity = "/proc-$procPosRelativeToNode/mc-$mc_num/".
                             "mi-$mi_num/mcc-$mcc_num/omi-$omi_num/".
                             "ocmb_chip-$ocmb_num/mem_port-$mem_num/".
                             "dimm-$ddimmPosPerParent";

        } # end foreach my $conn (@{$conn->{CONN}})
    } # end if ($conn ne "")

    # Get some useful info from the DDIMM parent's SYS and NODE and targets
    my $sysParent = $targetObj->findParentByType($target, "SYS");
    my $sysParentPos = $targetObj->getAttribute($sysParent, "ORDINAL_ID");
    my $nodeParent = $targetObj->findParentByType($target, "NODE");
    my $nodeParentPos = $targetObj->getAttribute($nodeParent, "ORDINAL_ID");
    my $nodeParentAffinity =$targetObj->getAttribute($nodeParent, "AFFINITY_PATH");
    my $nodeParentPhysical = $targetObj->getAttribute($nodeParent, "PHYS_PATH");

    my $staticAbsLocationCode = getStaticAbsLocationCode($targetObj,$target);
    $targetObj->setAttribute($target, "STATIC_ABS_LOCATION_CODE",$staticAbsLocationCode);

    # Get the FAPI_NAME by using the data gathered above.
    my $fapiName = $targetObj->getFapiName($type, $nodeParentPos, $dimmPosPerSystem);

    # Take advantage of previous work done on the NODEs.  Use the parent NODE's
    # affinity/physical path for our self and append the necessary data.
    $ddimmAffinity = $nodeParentAffinity . $ddimmAffinity;
    my $ddimmPhysical = $nodeParentPhysical . "/dimm-" . $dimmPosPerSystem;

    # Now that we collected all the data we need, set some target attributes
    $targetObj->setHuid($target, $sysParentPos, $nodeParentPos, $dimmPosPerSystem);
    $targetObj->setAttribute($target, "POSITION",      $dimmPosPerSystem);
    $targetObj->setAttribute($target, "ORDINAL_ID",    $dimmPosPerSystem);
    $targetObj->setAttribute($target, "FAPI_POS",      $dimmPosPerSystem);
    $targetObj->setAttribute($target, "FAPI_NAME",     $fapiName);
    $targetObj->setAttribute($target, "REL_POS",       $ddimmPosPerParent);
    $targetObj->setAttribute($target, "AFFINITY_PATH", $ddimmAffinity);
    $targetObj->setAttribute($target, "PHYS_PATH",     $ddimmPhysical);

    # Set the EEPROM_VPD_PRIMARY_INFO attribute for the DDIMM
    setEepromAttributeForDdimm($targetObj, $target);

    # Save this target for retrieval later when printing the xml (sub printXML)
    $targetObj->{targeting}{SYS}[0]{NODES}[$nodeParentPos]
                {DIMMS}[$dimmPosPerSystem]{KEY} = $target;

    # Mark this target as processed
    markTargetAsProcessed($targetObj, $target);

    ## Process children PMIC and OCMB. Children may differ for different systems.
    # Sanity check flag, to make sure that this code is still valid.
    my $foundPmic = false;
    my $foundOcmb = false;

    # If an error, such as 'Can't use string ("") as an ARRAY', then the
    # structure of the MRW has changed and this script needs updating.
    foreach my $child (@{ $targetObj->getTargetChildren($target) })
    {
        my $childTargetType = $targetObj->getTargetType($child);
        my $childType = $targetObj->getType($child);
        if ($childTargetType eq "chip-vreg-generic")
        {
            # Update TYPE to PMIC, because it is set to N/A and that won't fly
            $childType = $targetObj->setAttribute($child, "TYPE", "PMIC");
            processPmic($targetObj, $child);
            $foundPmic = true;
        }
        elsif ($childType eq "OCMB_CHIP")
        {
            processOcmbChipAndChildren($targetObj, $child);
            $foundOcmb = true;
        }
    }

    if ($foundPmic == false)
    {
        select()->flush(); # flush buffer before spewing out error message
        die "\nprocessDdimmAndChildren::ERROR: Did not find a \"PMIC\" " .
            "child for this DDIMM ($target). Did the MRW structure " .
            "change?  If so update this script to reflect changes.  Error"
    }

    if ($foundOcmb == false)
    {
        select()->flush(); # flush buffer before spewing out error message
        die "\nprocessDdimmAndChildren::ERROR: Did not find an \"OCMB\" " .
            "child for this DDIMM ($target). Did the MRW structure " .
            "change?  If so update this script to reflect changes.  Error"
    }
} # end sub processDdimmAndChildren

#--------------------------------------------------
# @brief Process targets of type PMIC
#
# @pre DIMM targets need to be processed beforehand
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The PMIC target
#--------------------------------------------------
sub processPmic
{
    my $targetObj = shift;
    my $target    = shift;

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target's parent has been processed.
    my $targetType = targetTypeSanityCheck($targetObj, $target, "PMIC");
    validateParentHasBeenProcessed($targetObj, $target);

    use constant MAX_PMIC_PER_DDIMM => 4;

    # PMICs are not ordered, so take the PMIC's parent DDIMM
    # position, multiply it by the maximum PMICs per DDIMM,
    # then add the PMIC's instance:
    # Ex. on a pmic0, dimm19 = pmic76   ((19 * 4) + 0)
    # Ex. on a pmic1, dimm19 = pmic77   ((19 * 4) + 1)
    # Ex. on a pmic2, dimm19 = pmic78   ((19 * 4) + 2)
    # Ex. on a pmic3, dimm19 = pmic79   ((19 * 4) + 3)

    # Get some useful data from the PMIC parent's SYS, NODE and DDIMM targets
    my $sysParent = $targetObj->findParentByType($target, "SYS");
    my $sysParentPos = $targetObj->getAttribute($sysParent, "ORDINAL_ID");
    my $nodeParent = $targetObj->findParentByType($target, "NODE");
    my $nodeParentPos = $targetObj->getAttribute($nodeParent, "ORDINAL_ID");
    my $nodeParentAffinity = $targetObj->getAttribute($nodeParent, "AFFINITY_PATH");
    my $nodeParentPhysical = $targetObj->getAttribute($nodeParent, "PHYS_PATH");
    my $ddimmParent = $targetObj->findParentByType($target, "DIMM");
    my $ddimmParentPos = $targetObj->getAttribute($ddimmParent, "POSITION");
    my $ddimmParentAffinity = $targetObj->getAttribute($ddimmParent, "AFFINITY_PATH");

    ## Get the instance name (pmic0, pmic1, etc) and extract the integral info.
    # Get the instance, then split on 'c' to isolate the integral value.
    # The integral value will be the last in the array that is returned from
    # the split, so do '[-1]' to extract that value.
    my $pmicInstanceName = $targetObj->getInstanceName($target);
    my $pmicInstancePos = (split('c', $pmicInstanceName))[-1];

    # Do a quick sanity check.  Make sure the PMIC instance position is less
    # than what is expected it to be.
    if ($pmicInstancePos >= MAX_PMIC_PER_DDIMM )
    {
        select()->flush(); # flush buffer before spewing out error message
        die "\nprocessPmic: ERROR: The PMIC's instance position " .
            "($pmicInstancePos), extracted from instance name " .
            "\"$pmicInstanceName\", exceeds or is equal to the maximum PMIC " .
            "per DIMM (" . MAX_PMIC_PER_DDIMM . "). Error" ;
    }

    # Calculate the PMIC position based on the DDIMM's position per system
    # and the PMIC instance position
    my $pmicPosPerSystem = ($ddimmParentPos * MAX_PMIC_PER_DDIMM) + $pmicInstancePos;

    # Get the FAPI_NAME by using the data gathered above
    my $fapiName = $targetObj->getFapiName($targetType, $nodeParentPos, $pmicPosPerSystem);

    # Take advantage of previous work done on the DDIMMs and NODEs.  Use these
    # parent affinity/physical path for our self and append pmic to the end.
    my $pmicAffinity = $ddimmParentAffinity;
    $pmicAffinity    =~ s/\/dimm-\d+//;     # Drop the dimm info, not needed
    $pmicAffinity    =~ s/\/mem_port-\d+//; # Drop the mem_port info, not needed
    $pmicAffinity    = $pmicAffinity . "/pmic-" . $pmicInstancePos;
    my $pmicPhysical = $nodeParentPhysical . "/pmic-" . $pmicPosPerSystem;

    # The FRU_ID comes from the parent ddimm
    my $fruId = $targetObj->getAttribute($ddimmParent, "FRU_ID");

    # Now that we collected all the data we need, set some target attributes
    $targetObj->setHuid($target, $sysParentPos, $nodeParentPos, $pmicPosPerSystem);
    $targetObj->setAttribute($target, "POSITION",      $pmicPosPerSystem);
    $targetObj->setAttribute($target, "ORDINAL_ID",    $pmicPosPerSystem);
    $targetObj->setAttribute($target, "FAPI_POS",      $pmicPosPerSystem);
    $targetObj->setAttribute($target, "FAPI_NAME",     $fapiName);
    $targetObj->setAttribute($target, "REL_POS",       $pmicInstancePos);
    $targetObj->setAttribute($target, "AFFINITY_PATH", $pmicAffinity);
    $targetObj->setAttribute($target, "PHYS_PATH",     $pmicPhysical);
    $targetObj->setAttribute($target, "FRU_ID",        $fruId);

    # Set the FAPI_I2C_CONTROL_INFO attribute
    setFapi2AttributeForPmic($targetObj, $target);

    # Save this target for retrieval later when printing the xml (sub printXML)
    $targetObj->{targeting}{SYS}[$sysParentPos]{NODES}[$nodeParentPos]
                {PMICS}[$pmicPosPerSystem]{KEY} = $target;

    # Mark this target as processed
    markTargetAsProcessed($targetObj, $target);
} # end sub processPmic

#--------------------------------------------------
# @brief Process targets of type OCMB_CHIP and it's child MEM_PORT
#
# @pre DIMM targets need to be processed beforehand
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The OCMB_CHIP target
#--------------------------------------------------
sub processOcmbChipAndChildren
{
    my $targetObj = shift;
    my $target    = shift;

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target's parent has been processed.
    my $type = targetTypeSanityCheck($targetObj, $target, "OCMB_CHIP");
    validateParentHasBeenProcessed($targetObj, $target);

    # Get some useful info from the OCMB parent's SYS, NODE and DDIMM targets.
    my $sysParent = $targetObj->findParentByType($target, "SYS");
    my $sysParentPos = $targetObj->getAttribute($sysParent, "ORDINAL_ID");
    my $nodeParent = $targetObj->findParentByType($target, "NODE");
    my $nodeParentPos = $targetObj->getAttribute($nodeParent, "ORDINAL_ID");
    my $nodeParentPhysical = $targetObj->getAttribute($nodeParent, "PHYS_PATH");
    my $nodeParentAffinity = $targetObj->getAttribute($nodeParent, "AFFINITY_PATH");
    my $ddimmParent = $targetObj->findParentByType($target, "DIMM");

    # Use the parent's DDIMM's position, per system, to set the OCMB's
    # position, per system. IE, the position is an increasing sequential
    # number, starting at 0, and ending with the last OCMB for the system
    # (target type SYS).
    my $ocmbPosPerSystem = $targetObj->getAttribute($ddimmParent, "POSITION");

    # Use the OCMB's position per system to calculate the OCMB's position per
    # parent.  This is done by taking the modulo of the OCMB's position per
    # system against the maximum instance per parent.
    my $ocmbPosPerParent = $ocmbPosPerSystem % getMaxInstPerParent($type);

    # Get the FAPI_NAME by using the data gathered above.
    my $fapiName = $targetObj->getFapiName($type, $nodeParentPos, $ocmbPosPerSystem);

    # Take advantage of previous work done on the DDIMMs.  Use the parent DDIMM's
    # affinity path for our self, but remove trailing parts we don't want/need.
    my $ocmbAffinity = $targetObj->getAttribute($ddimmParent, "AFFINITY_PATH");
    $ocmbAffinity =~ s/\/dimm.*//g;
    $ocmbAffinity =~ s/\/mem_port.*//g;

    # Use the parent NODE's physical path to set the OCMB's physical path
    my $ocmbPhysical = $nodeParentPhysical . "/ocmb_chip-" . $ocmbPosPerSystem;

    # The FRU_ID comes from the parent ddimm
    my $fruId = $targetObj->getAttribute($ddimmParent, "FRU_ID");

    # Now that we collected all the data we need, set some target attributes
    $targetObj->setHuid($target, $sysParentPos, $nodeParentPos, $ocmbPosPerSystem);
    $targetObj->setAttribute($target, "POSITION",      $ocmbPosPerSystem);
    $targetObj->setAttribute($target, "VPD_REC_NUM",   $ocmbPosPerSystem);
    $targetObj->setAttribute($target, "FAPI_POS",      $ocmbPosPerSystem);
    $targetObj->setAttribute($target, "FAPI_NAME",     $fapiName);
    $targetObj->setAttribute($target, "AFFINITY_PATH", $ocmbAffinity);
    $targetObj->setAttribute($target, "PHYS_PATH",     $ocmbPhysical);
    $targetObj->setAttribute($target, "FRU_ID",        $fruId);

    # Set the EEPROM_VPD_PRIMARY_INFO and FAPI_I2C_CONTROL_INFO attributes
    setEepromAndFapi2AttributesForOcmb($targetObj, $target);

    # Save this target for retrieval later when printing the xml (sub printXML)
    $targetObj->{targeting}{SYS}[$sysParentPos]{NODES}[$nodeParentPos]
                {OCMB_CHIPS}[$ocmbPosPerSystem]{KEY} = $target;

    # Mark this target as processed
    markTargetAsProcessed($targetObj, $target);

    ## Process child MEM_PORT. Children may differ for different systems.
    # Sanity check flag, to make sure that this code is still valid.
    my $foundMemPort = false;

    # If an error, such as 'Can't use string ("") as an ARRAY', then the
    # structure of the MRW has changed and this script needs updating.
    foreach my $child (@{ $targetObj->getTargetChildren($target) })
    {
        if ( ($targetObj->getType($child)) eq "MEM_PORT")
        {
            processMemPort($targetObj, $child);
            $foundMemPort = true;
        }
    }

    if ($foundMemPort == false)
    {
        select()->flush(); # flush buffer before spewing out error message
        die "\nprocessOcmbChipAndChildren::ERROR: Did not find a \"MEM_PORT\" " .
            "child for this OCMB_CHIP ($target). Did the MRW structure " .
            "change?  If so update this script to reflect changes.  Error"
    }
} # end sub processOcmbChipAndChildren

#--------------------------------------------------
# @brief Process targets of type MEM_PORT
#
# @pre DIMM targets need to be processed beforehand
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The MEM_PORT target
#--------------------------------------------------
sub processMemPort
{
    my $targetObj = shift;
    my $target    = shift;

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target's parent has been processed.
    my $type = targetTypeSanityCheck($targetObj, $target, "MEM_PORT");
    validateParentHasBeenProcessed($targetObj, $target);

    # Get some useful info from the MEM_PORT parent's SYS, NODE and DDIMM targets
    my $sysParent = $targetObj->findParentByType($target, "SYS");
    my $sysParentPos = $targetObj->getAttribute($sysParent, "ORDINAL_ID");
    my $nodeParent = $targetObj->findParentByType($target, "NODE");
    my $nodeParentPos = $targetObj->getAttribute($nodeParent, "ORDINAL_ID");
    my $ddimmParent = $targetObj->getTargetParent($target);
    my $ddimmParentAffinity = $targetObj->getAttribute($ddimmParent, "AFFINITY_PATH");
    my $ddimmParentPhysical = $targetObj->getAttribute($ddimmParent, "PHYS_PATH");

    # Use the parent DDIMM's position, per system, to set the MEM_PORT's
    # position, per system. IE, the position is an increasing sequential
    # number, starting at 0, and ending with the last MEM_PORT for the system
    # (target type SYS).
    my $memPortPosPerSystem = $targetObj->getAttribute($ddimmParent, "POSITION");

    # Use the MEM_PORT's position per system to calculate the MEM_PORT's
    # position per parent.  This is done by taking the modulo of the MEM_PORT's
    # position per system against the maximum instance per parent.
    my $memPortPosPerParent = $memPortPosPerSystem % getMaxInstPerParent($type);

    # Get the FAPI_NAME by using the data gathered above.
    my $chipPos = 0; # The chip position for MEM_PORT is 0
    my $fapiName  = $targetObj->getFapiName($type, $nodeParentPos, $chipPos, $memPortPosPerSystem);

    # Take advantage of previous work done on the DDIMMs.  Use the parent DDIMM's
    # affinity/physical path for our self and append the mem_port to the end.
    my $memPortAffinity = $ddimmParentAffinity . "/mem_port-" . $memPortPosPerParent;
    my $memPortPhysical = $ddimmParentPhysical . "/mem_port-" . $memPortPosPerParent;

    # Now that we collected all the data we need, set some target attributes
    $targetObj->setHuid($target, $sysParentPos, $nodeParentPos, $memPortPosPerSystem);
    $targetObj->setAttribute($target, "FAPI_POS",      $memPortPosPerSystem);
    $targetObj->setAttribute($target, "FAPI_NAME",     $fapiName);
    $targetObj->setAttribute($target, "REL_POS",       $memPortPosPerParent);
    $targetObj->setAttribute($target, "AFFINITY_PATH", $memPortAffinity);
    $targetObj->setAttribute($target, "PHYS_PATH",     $memPortPhysical);

    # Save this target for retrieval later when printing the xml (sub printXML)
    $targetObj->{targeting}{SYS}[$sysParentPos]{NODES}[$nodeParentPos]
                {MEM_PORTS}[$memPortPosPerSystem]{KEY} = $target;

    # Mark this target as processed
    markTargetAsProcessed($targetObj, $target);
} # end sub processMemPort

#--------------------------------------------------
# @brief Process targets of type BMC
#
# @pre SYS, NODE and PROC targets need to be processed beforehand
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The BMC target
#--------------------------------------------------
sub processBmc
{
    my $targetObj = shift;
    my $target    = shift;

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target's parent has been processed.
    my $type = targetTypeSanityCheck($targetObj, $target, "BMC");
    validateParentHasBeenProcessed($targetObj, $target, "NODE");

    # Get some useful info from the BMC parent's SYS and NODE targets
    my $sysParent = $targetObj->findParentByType($target, "SYS");
    my $sysParentPos = $targetObj->getAttribute($sysParent, "ORDINAL_ID");
    my $nodeParent = $targetObj->findParentByType($target, "NODE");
    my $nodeParentPos = $targetObj->getAttribute($nodeParent, "ORDINAL_ID");
    my $nodeParentAffinity = $targetObj->getAttribute($nodeParent, "AFFINITY_PATH");
    my $nodeParentPhysical = $targetObj->getAttribute($nodeParent, "PHYS_PATH");

    # Get the BMC's position for further use below
    my $bmcPosPerSystem = $targetObj->getTargetPosition($target);

    # Get the FAPI_NAME
    my $fapiName  = $targetObj->getFapiName($type);

    # Take advantage of previous work done on the NODEs.  Use the parent NODE's
    # affinity/physical path for our self and append bmc to the end.
    my $bmcAffinity = $nodeParentAffinity . "/bmc-" . $bmcPosPerSystem;
    my $bmcPhysical = $nodeParentPhysical . "/bmc-" . $bmcPosPerSystem;

    # Now that we collected all the data we need, set some target attributes
    $targetObj->setHuid($target, $sysParentPos, $nodeParentPos, $bmcPosPerSystem);
    $targetObj->setAttribute($target, "ORDINAL_ID",    $bmcPosPerSystem);
    $targetObj->setAttribute($target, "FAPI_POS",      $bmcPosPerSystem);
    $targetObj->setAttribute($target, "FAPI_NAME",     $fapiName);
    $targetObj->setAttribute($target, "AFFINITY_PATH", $bmcAffinity);
    $targetObj->setAttribute($target, "PHYS_PATH",     $bmcPhysical);

    # Save this target for retrieval later when printing the xml (sub printXML)
    $targetObj->{targeting}{SYS}[$sysParentPos]{NODES}[$nodeParentPos]
                {BMC}[$bmcPosPerSystem]{KEY} = $target;

    # Mark this target as processed
    markTargetAsProcessed($targetObj, $target);
} # end sub processBMC


#--------------------------------------------------
# @brief Process targets of type POWER_SEQUENCER (UCD)
#
# @pre SYS, NODE and PROC targets need to be processed beforehand
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The POWER_SEQUENCER target
#--------------------------------------------------
sub processUcd
{
    my $targetObj = shift;
    my $target    = shift;

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target's parent has been processed.
    my $type = targetTypeSanityCheck($targetObj, $target, "POWER_SEQUENCER");
    validateParentHasBeenProcessed($targetObj, $target);

    # Get some useful info from the BMC parent's SYS and NODE targets
    my $sysParent = $targetObj->findParentByType($target, "SYS");
    my $sysParentPos = $targetObj->getAttribute($sysParent, "ORDINAL_ID");
    my $nodeParent = $targetObj->findParentByType($target, "NODE");
    my $nodeParentPos = $targetObj->getAttribute($nodeParent, "ORDINAL_ID");
    my $nodeParentAffinity = $targetObj->getAttribute($nodeParent, "AFFINITY_PATH");
    my $nodeParentPhysical = $targetObj->getAttribute($nodeParent, "PHYS_PATH");

    # Get the UCD's position for further use below
    my $ucdPosPerSystem = $targetObj->getTargetPosition($target);

    # Take advantage of previous work done on the NODEs.  Use the parent NODE's
    # physical path for our self and append power_sequencer to the end.
    # Use method getParentProcAffinityPath to get the UCD's affinity path.
    my $ucdAffinity = getParentProcAffinityPath($targetObj, $target, $ucdPosPerSystem, $type);
    my $ucdPhysical = $nodeParentPhysical . "/power_sequencer-" . $ucdPosPerSystem;

    # Now that we collected all the data we need, set some target attributes
    $targetObj->setHuid($target, $sysParentPos, $nodeParentPos, $ucdPosPerSystem);
    $targetObj->setAttribute($target, "ORDINAL_ID",    $ucdPosPerSystem);
    $targetObj->setAttribute($target, "AFFINITY_PATH", $ucdAffinity);
    $targetObj->setAttribute($target, "PHYS_PATH",     $ucdPhysical);

    # @TODO RTC 201991: remove these overrides when the MRW is updated
    $targetObj->setAttribute($target, "CLASS", "ASIC");
    $targetObj->deleteAttribute($target, "POSITION");
    $targetObj->deleteAttribute($target, "FRU_ID");

    # Save this target for retrieval later when printing the xml (sub printXML)
    $targetObj->{targeting}{SYS}[$sysParentPos]{NODES}[$sysParentPos]
                {UCDS}[$ucdPosPerSystem]{KEY} = $target;

    # Mark this target as processed
    markTargetAsProcessed($targetObj, $target);
} # end sub processUcd

#--------------------------------------------------
# @brief Process targets of type TPM
#
# @pre SYS, NODE and PROC targets need to be processed beforehand
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The TPM target
#--------------------------------------------------
sub processTpm
{
    my $targetObj = shift;
    my $target    = shift;

    my $type = targetTypeSanityCheck($targetObj, $target, "TPM");

    # Get some useful info from the TPM parent's SYS and NODE targets
    my $sysParent = $targetObj->findParentByType($target, "SYS");
    my $sysParentPos = $targetObj->getAttribute($sysParent, "ORDINAL_ID");
    my $nodeParent = $targetObj->findParentByType($target, "NODE");
    my $nodeParentPos = $targetObj->getAttribute($nodeParent, "ORDINAL_ID");
    my $nodeParentAffinity = $targetObj->getAttribute($nodeParent, "AFFINITY_PATH");
    my $nodeParentPhysical = $targetObj->getAttribute($nodeParent, "PHYS_PATH");

    my $staticAbsLocationCode = getStaticAbsLocationCode($targetObj,$target);
    $targetObj->setAttribute($target, "STATIC_ABS_LOCATION_CODE",$staticAbsLocationCode);

    # Get the TPM's position for further use below
    my $tpmPosPerSystem = $targetObj->getTargetPosition($target);

    # Get the FAPI_NAME
    my $fapiName  = $targetObj->getFapiName($type);

    # Take advantage of previous work done on the NODEs.  Use the parent NODE's
    # physical path for our self and append tpm to the end.  Use method
    # getParentProcAffinityPath to get the TPM's affinity path.
    my $tpmAffinity = getParentProcAffinityPath($targetObj, $target, $tpmPosPerSystem, $type);
    my $tpmPhysical = $nodeParentPhysical . "/tpm-" . $tpmPosPerSystem;

    # Now that we collected all the data we need, set some target attributes
    $targetObj->setHuid($target, $sysParentPos, $nodeParentPos, $tpmPosPerSystem);
    $targetObj->setAttribute($target, "ORDINAL_ID",    $tpmPosPerSystem);
    $targetObj->setAttribute($target, "FAPI_POS",      $tpmPosPerSystem);
    $targetObj->setAttribute($target, "FAPI_NAME",     $fapiName);
    $targetObj->setAttribute($target, "AFFINITY_PATH", $tpmAffinity);
    $targetObj->setAttribute($target, "PHYS_PATH",     $tpmPhysical);

    # Save this target for retrieval later when printing the xml (sub printXML)
    $targetObj->{targeting}{SYS}[$nodeParentPos]{NODES}[$nodeParentPos]
                {TPMS}[$tpmPosPerSystem]{KEY} = $target;
} # end sub processTpm

################################################################################
# Subroutines that support the processing subroutines
################################################################################
sub iterateOverChiplets
{
    my $targetObj = shift;
    my $target    = shift;
    my $sys       = shift;
    my $node      = shift;
    my $proc      = shift;
    my $tgt_ptr   = $targetObj->getTarget($target);
    my $tgt_type  = $targetObj->getType($target);

    my $target_children  = $targetObj->getTargetChildren($target);

    if ($target_children eq "")
    {
        return "";
    }
    else
    {
        my @phb_array = ();
        my @non_connected_phb_array = ();
        foreach my $child (@{ $targetObj->getTargetChildren($target) })
        {
            # For PEC children, we need to remove duplicate PHB targets
            if ($tgt_type eq "PEC")
            {
                my $pec_num = $targetObj->getAttribute($target, "CHIP_UNIT");
                $targetObj->setAttribute($child,"AFFINITY_PATH",$targetObj
                    ->getAttribute($target,"AFFINITY_PATH"));
                $targetObj->setAttribute($child,"PHYS_PATH",$targetObj
                    ->getAttribute($target,"PHYS_PATH"));

                foreach my $phb (@{ $targetObj->getTargetChildren($child) })
                {
                    my $phb_num = $targetObj->getAttribute($phb, "CHIP_UNIT");
                    foreach my $pcibus (@{ $targetObj->getTargetChildren($phb) })
                    {
                        # We need to ensure that all PHB's get added to the
                        # MRW, but PHB's with busses connected take priority
                        # and we cannot have duplicate PHB targets in the MRW.

                        # We processes every PHB pci bus config starting with
                        # the config with the fewest PHB's. For PEC2 we start
                        # with PHB3_x16. If a bus is not connected to that PHB
                        # we add it to the phb_array anyway so the target will
                        # be populated in the HB MRW. As we processes the later
                        # PHB configs under PEC2 we may find that PHB3 has a
                        # bus connected to it. Since the bus config takes
                        # priority over the target that was already added to
                        # the phb_array, we just overwrite that phb_array entry
                        # with the PHB that has a bus connected.

                        if (($targetObj->getNumConnections($pcibus) > 0) &&
                                (@phb_array[$phb_num] eq ""))
                        {
                            # This PHB does have a bus connection and the slot
                            # is empty. We must add it to the PHB array
                            @phb_array[$phb_num] = $phb;
                        }
                        elsif (($targetObj->getNumConnections($pcibus) == 0) &&
                                   (@phb_array[$phb_num] eq ""))
                        {
                            # This PHB does NOT have a bus connection. It's
                            # slot is still empty, so we must add it to the
                            # array so every PHB has a target in the MRW.
                            @phb_array[$phb_num] = $phb;

                            # Also add it to the non_connected_phb_array so we
                            # can examine later it if needs to be overriden.
                            @non_connected_phb_array[$phb_num] = $phb;
                        }
                        elsif (($targetObj->getNumConnections($pcibus) > 0) &&
                                   (@phb_array[$phb_num] ne ""))
                        {
                             # This PHB has a connection, but the slot has
                             # already been filled by another PHB. We need to
                             # check if it was a non connected PHB
                             if(@non_connected_phb_array[$phb_num] ne "")
                             {
                                 # The previous connection in the PHB elecment
                                 # is not connected to a bus. We should
                                 # override it
                                 @phb_array[$phb_num] = $phb;
                             }
                             else
                             {
                                 # This is our "bug" scenerio. We have found a
                                 # connection, but that PHB element is already
                                 # filled in the array. We need to kill the
                                 # program.
                                 printf("Found a duplicate connection for PEC %s PHB %s.\n",$pec_num,$phb_num);
                                 select()->flush(); # flush buffer before spewing out error message
                                 die "Duplicate PHB bus connection found\n";
                             }
                        } # end elsif (($targetObj->getNumConnections ...
                    } # end foreach my $pcibus ...
                } # end foreach my $phb (@{ $targetObj->getTargetChildren($child) })
                # Mark this target as processed
                markTargetAsProcessed($targetObj, $target);
            } # end if ($tgt_type eq "PEC")
            else
            {
                # These target types are NOT PEC
                my $unit_ptr  = $targetObj->getTarget($child);
                my $unit_type = $targetObj->getType($child);

                #System XML has some sensor target as hidden children
                #of targets. We don't care for sensors in this function
                #So, we can avoid them with this conditional
                if ($unit_type ne "PCI" && $unit_type ne "NA" &&
                    $unit_type ne "FSI" && $unit_type ne "PSI" &&
                    $unit_type ne "SYSREFCLKENDPT" &&
                    $unit_type ne "PCICLKENDPT" &&
                    $unit_type ne "LPCREFCLKENDPT")
                {

                    # @TODO Remove this check once ABUS and XBUS
                    # have been removed from the MRW
                    if (($targetObj->getType($child) ne "ABUS") &&
                        ($targetObj->getType($child) ne "XBUS") )
                    {
                        #set common attrs for child
                        setCommonAttrForChiplet($targetObj, $child,
                                                $sys, $node, $proc);

                        # Mark this target as processed
                        markTargetAsProcessed($targetObj, $target);

                        iterateOverChiplets($targetObj, $child, $sys, $node, $proc);
                    }
                } # end if ($unit_type ne "PCI" && ...
            } # end if ($tgt_type eq "PEC") ... else
        } # end foreach my $child (@{ $targetObj->getTargetChildren($target) })

        my $size = @phb_array;
        # For every entry in the PHB array, if there is a PHB in its slot
        # we add that PHB target to the MRW.

        # We process PEC's individually, so we need to make sure the PHB slot
        # has a PHB in it. eg: phb_array[0] will be empty for when processing
        # PEC1 and 2 as there is no PHB0 configured for those PECs.
        for (my $i = 0; $i < $size; $i++)
        {
            if (@phb_array[$i] ne "")
            {
                setCommonAttrForChiplet
                    ($targetObj, @phb_array[$i], $sys, $node, $proc);
                # Mark this target as processed
                markTargetAsProcessed($targetObj, $target);
            }
        }
    } # end if ($target_children eq "") ... else
} # end sub iterateOverChiplets

#--------------------------------------------------
# @brief Set a list of common attributes for the given target
#
# @detail The attributes set for given target are CHIPLET_ID, ORDINAL_ID,
#         FAPI_POS, FAPI_NAME, REL_POS, AFFINITY_PATH, PHYS_PATH and
#         PARENT_PERVASIVE
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The target to set attributes of
# @param[in] $sysPos    - The parent SYS target position
# @param[in] $nodePos   - The parent NODE target position
# @param[in] $procPos   - The parent PROC target position
#--------------------------------------------------
sub setCommonAttrForChiplet
{
    my $targetObj = shift;
    my $target    = shift;
    my $sysPos    = shift;
    my $nodePos   = shift;
    my $procPos   = shift;

    my $targetType  = $targetObj->getType($target);
    # Make sure the target's parent has been processed.
    if ($targetType eq "PHB")
    {
        # Special case: PHB is one removed from target type PEC
        validateParentHasBeenProcessed($targetObj, $target, "PEC");
    }
    else
    {
        validateParentHasBeenProcessed($targetObj, $target);
    }

    # Targets have the CHIP_UNIT (target position) attribute set, for the first
    # PROC, which allows for all of the other numerical data to calculated.
    my $targetPos = $targetObj->getAttribute($target, "CHIP_UNIT");

    # Calculate a per parent numerical value.  The per parent numerical value
    # is used to populate the AFFINITY_PATH, PHYS_PATH and REL_PATH.
    my $perParentNumValue = $targetPos % getMaxInstPerParent($targetType);

    # Calculate a per PROC numerical value.  The per PROC numerical value
    # is used to populate the HUID.
    my $perProcNumValue = ($procPos * getMaxInstPerProc($targetType)) + $targetPos;

    # Get a per SYS numerical value.  The per SYS numerical value is used
    # to populate the attributes ORDINAL_ID and FAPI_POS.
    my $perSysNumValue = ($nodePos  * getMaxInstPerParent("PROC") *
                      getMaxInstPerProc($targetType)) + $perProcNumValue;

    # Get the FAPI_NAME by using the data gathered above.
    my $fapiName = $targetObj->getFapiName($targetType, $nodePos, $procPos, $targetPos);

    # Get the parent, to extract the affinity and physical path from.
    my $targetParent = $targetObj->getTargetParent($target);

    # Special case: OMI has 2 parents, OMIC and MCC.  Use the paths from MCC parent.
    if ($targetType eq "OMI")
    {
        $targetParent = $targetObj->findParentByType($target, "MCC");
    }
    # Special case: For the OMIC, use the paths from MC parent
    elsif ($targetType eq "OMIC")
    {
        $targetParent = $targetObj->findParentByType($target, "MC");
    }

    # Now that parent thing is sorted, retrieve the parent's affinity/physical paths.
    my $parentAffinity = $targetObj->getAttribute($targetParent, "AFFINITY_PATH");
    my $parentPhysical = $targetObj->getAttribute($targetParent, "PHYS_PATH");

    # Construct the target's physical/affinity path with the retrieved data above
    my $targetAffinity = "$parentAffinity/" . lc $targetType . "-$perParentNumValue";
    my $targetPhysical = "$parentPhysical/" . lc $targetType . "-$perParentNumValue";

    # Now that we collected all the data we need, set some target attributes
    $targetObj->setHuid($target, $sysPos, $nodePos, $perProcNumValue);
    $targetObj->setAttribute($target, "ORDINAL_ID",    $perSysNumValue);
    $targetObj->setAttribute($target, "FAPI_POS",      $perSysNumValue);
    $targetObj->setAttribute($target, "FAPI_NAME",     $fapiName);
    $targetObj->setAttribute($target, "REL_POS",       $perParentNumValue);
    $targetObj->setAttribute($target, "AFFINITY_PATH", $targetAffinity);
    $targetObj->setAttribute($target, "PHYS_PATH",     $targetPhysical);

    my $pervasive_parent= getPervasiveForUnit($targetObj, "$targetType$targetPos");
    if ($pervasive_parent ne "")
    {
        # Special case: FC does not have a PARENT_PERVASIVE
        if ($targetType ne "FC")
        {
            my $perv_parent_val =
                "physical:sys-$sysPos/node-$nodePos/proc-$procPos/perv-$pervasive_parent";
            $targetObj->setAttribute($target, "PARENT_PERVASIVE", $perv_parent_val);
        }

        my $value = sprintf("0x%0.2X", $pervasive_parent);
        $targetObj->setAttribute($target, "CHIPLET_ID", $value);
    }

    # Special case: PAU's ORDINAL_ID's needs to be calculated
    if ($targetType eq "PAU")
    {
        setPauOrdinalId($targetObj, $target);
    }

    # Save this target for retrieval later when printing the xml (sub printXML)
    push(@{$targetObj->{targeting}
            ->{SYS}[$sysPos]{NODES}[$nodePos]{PROCS}[$procPos]{$targetType}},
            { 'KEY' => $target });

    # Mark this target as processed
    markTargetAsProcessed($targetObj, $target);
} # end sub setCommonAttrForChiplet

#--------------------------------------------------
# @brief Set the PROC master status
#
# @detail Setting the PROC master status to either 'not master' or
#         'acting master'.
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The PROC target
#--------------------------------------------------
sub setProcMasterStatus
{
    my $targetObj = shift;
    my $target    = shift;

    $targetObj->log($target,"Finding master proc (looking for LPC Bus)");

    # Default the PROC to not be the master.  This is the predominate case
    $targetObj->setAttribute($target, "PROC_MASTER_TYPE", "NOT_MASTER");
    $targetObj->setAttribute($target, "PROC_SBE_MASTER_CHIP", "FALSE");

    # Both for FSP and BMC based systems, it's good  enough
    # to look for processor with active LPC bus connected
    my $lpcs = $targetObj->findConnections($target, "LPC", "");

    # If LPC found, then this PROC is the master
    if ($lpcs ne "")
    {
        $targetObj->log ($target, "Setting $target as ACTING_MASTER");
        $targetObj->setAttribute($target, "PROC_MASTER_TYPE", "ACTING_MASTER");
        $targetObj->setAttribute($target, "PROC_SBE_MASTER_CHIP", "TRUE");
    }
} # end sub setProcMasterStatus

#--------------------------------------------------
# @brief Finds the number of processors per socket in the system mrw by counting
#        the number of procs under the socket target.
#        NOTE: This function only needs to be called once and that occurs in
#              processProcessorAndChildren(). This will create and set the
#              variable NUMBER_PROCS_PER_SOCKET in the global target object.
#
# @param[in] $targetObj - The global target object blob
# @param[in] $proc      - The PROC target
#
# @return    $numberOfProcsPerSocket - The number of procs per socket.
#--------------------------------------------------
sub findProcPerSocket
{
    my $targetObj = shift;
    my $proc      = shift;

    my $parent = $proc;
    $parent = $targetObj->getTargetParent($proc);

    my $numberOfProcsPerSocket = 0;
    foreach my $child (@{ $targetObj->getTargetChildren($parent) })
    {
        if ($targetObj->doesAttributeExistForTarget($child, "TYPE"))
        {
            my $type = $targetObj->getType($child);
            if ($type eq "PROC")
            {
                $numberOfProcsPerSocket++;
            }
        }
    }

    # Dynamically create and cache the number of procs per socket.
    $targetObj->{NUMBER_PROCS_PER_SOCKET} = $numberOfProcsPerSocket;

    return $numberOfProcsPerSocket;
}

#--------------------------------------------------
# @brief Calculates the processor position with respect to the node it is a
#        child of.
#
# @param[in] $targetObj                    - The global target object blob.
# @param[in] $socketPosition               - The socket position relative to the
#                                            node parent.
# @param[in] $procPositionRelativeToSocket - The proc position relative to the
#                                            socket parent.
# @return $procPosRelativeToNode           - The procs position relative to the
#                                            node parent.
#--------------------------------------------------
sub calculateProcPositionPerNode
{
    my $targetObj = shift;
    my $socketPosition = shift;
    my $procPositionRelativeToSocket = shift;

    my $procPosRelativeToNode = ($socketPosition
                              * $targetObj->{NUMBER_PROCS_PER_SOCKET})
                              + $procPositionRelativeToSocket;

    return $procPosRelativeToNode;
}

# Get the affinity path of the passed target. The affinity path is the physical
# path of the target's I2C master which for this function is the parent
# processor with chip unit number appended.
sub getParentProcAffinityPath
{
    my $targetObj = shift;
    my $target    = shift;
    my $chip_unit = shift;
    my $type_name = shift;

    # Make sure the type_name is all upper-case
    my $type_name = uc $type_name;

    # Create a lower-case version of the type name
    my $lc_type_name = lc $type_name;

    my $affinity_path = "";

    # Only get affinity path for supported types.
    if(($type_name ne "TPM")
      && ($type_name ne "POWER_SEQUENCER"))
    {
        select()->flush(); # flush buffer before spewing out error message
        die "Attempted to get parent processor affinity path" .
            " on invalid target ($type_name)";
    }

    my $parentProcsPtr = $targetObj->findDestConnections($target, "I2C", "");

    if($parentProcsPtr eq "")
    {
        $affinity_path = "affinity:sys-0/node-0/proc-0/" .
                         "$lc_type_name-$chip_unit";
    }
    else
    {
        my @parentProcsList = @{$parentProcsPtr->{CONN}};
        my $numConnections = scalar @parentProcsList;

        if($numConnections != 1)
        {
            select()->flush(); # flush buffer before spewing out error message
            die "Incorrect number of parent procs ($numConnections)".
                " found for $type_name$chip_unit";
        }

        # The target is only connected to one proc, so we can fetch just the
        # first connection.
        my $parentProc = $parentProcsList[0]{SOURCE_PARENT};
        if($targetObj->getAttribute($parentProc, "TYPE") ne "PROC")
        {
            select()->flush(); # flush buffer before spewing out error message
            die "Upstream I2C connection to $type_name" .
                "$chip_unit is not type PROC!";
        }

        # Look at the I2C master's physical path; replace
        # "physical" with "affinity" and append chip unit
        $affinity_path = $targetObj->getAttribute($parentProc, "PHYS_PATH");
        $affinity_path =~ s/physical/affinity/g;
        $affinity_path = $affinity_path . "/$lc_type_name-$chip_unit";
    }

    return $affinity_path;
} # end sub getParentProcAffinityPath

#--------------------------------------------------
# @brief Set the EEPROM_VPD_PRIMARY_INFO attribte for the given DDIMM
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The DDIMM target
#--------------------------------------------------
sub setEepromAttributeForDdimm
{
    my $targetObj = shift;
    my $target    = shift;

    # Sanity check.  Make sure we are processing the correct target type.
    targetTypeSanityCheck($targetObj, $target, "DIMM");

    # Find the child SPD (type chip-spd-device).  If not found then
    # throw an error
    my $spdDevice = "";
    foreach my $child (@{ $targetObj->getTargetChildren($target) })
    {
        if ($targetObj->getTargetType($child) eq "chip-spd-device")
        {
            $spdDevice = $child;
            last;
        }
    }

    # Throw error if a SPD was not found and exit
    if ($spdDevice eq "")
    {
        select()->flush(); # flush buffer before spewing out error message
        die "\nsetEepromAttributeForDdimm: ERROR: Expected to find an SPD type " .
            "chip-spd-device for DDIMM ($target).\nError";
    }

    # Find connections for target ($spdDevice) of bus type ("I2C"), ignore
    # connections FROM this target ("") but find connections TO this target(1).
    # If not found, then throw an error and exit.
    my $i2cConn = $targetObj->findConnectionsByDirection($spdDevice, "I2C", "", 1);

    if ($i2cConn eq "")
    {
        select()->flush(); # flush buffer before spewing out error message
        die "\nsetEepromAttributeForDdimm: ERROR: Expected to find an I2C " .
            "connection for DDIMM ($target).\nError";
    }

    my $connectionFound = 0;

    # To get the correct i2c connection we must verify that we are getting the
    # PIB connection type and not the CFAM connection. Rainier and Denali both
    # use the PIB connection but Denali has a CFAM connection as well.
    foreach my $connection (@{$i2cConn->{CONN}})
    {
        my $connectionType = $targetObj->getAttribute($connection->{SOURCE},
                                                      "I2C_CONNECTION_TYPE");
        if ($connectionType eq "PIB")
        {
            $i2cConn = $connection;
            $connectionFound = 1;
            last;
        }
    }

    if ($connectionFound == 0)
    {
        print "\nsetEepromAttributeForDdimm: ERROR: Expected to find a ".
            "PIB I2C connection for DIMM ($target).".
            "\nPotential MRW I2C_CONNECTION_TYPE error.";
        print"\n Connections for this DIMM:";
        foreach my $connection (@{$i2cConn->{CONN}})
        {
            print "\n". Dumper($connection);
            my $type = $targetObj->getAttribute($connection->{SOURCE},
                                                "I2C_CONNECTION_TYPE");
            print "\n Connection Type: ". $type ."\n";
        }
        select()->flush();
        die;
    }

    # Sanity check,  Make sure destination target is the same as given target
    my $destTarget = $targetObj->getTargetParent($i2cConn->{DEST_PARENT});
    if ($destTarget ne $target)
    {
        select()->flush(); # flush buffer before spewing out error message
        die "\nsetEepromAttributeForDdimm: ERROR: Expected destination target " .
            "($destTarget) to be the same as the given target ($target).\nError";
    }

    setEepromAttribute($targetObj, $target, "EEPROM_VPD_PRIMARY_INFO", $i2cConn);
} # end setEepromAttributeForDdimm


#--------------------------------------------------
# @brief Set the EEPROM fields for given target and given EEPROM attrubute
#
# @param[in] $targetObj  - The global target object blob
# @param[in] $target     - The target to set the EEPROM attribute for
# @param[in] $eepromName - The name of the EEPROM attribute (EEPROM_VPD_PRIMARY_INFO, etc)
# @param[in] $i2cConn    - The I2C connection
#--------------------------------------------------
sub setEepromAttribute
{
    my $targetObj = shift;
    my $target = shift;
    my $eepromName = shift;
    my $i2cConn = shift;

    # Gather the individual field data for the named EEPROM attribute
    my $byteAddrOffset = $targetObj->getAttribute($i2cConn->{DEST_PARENT}, "BYTE_ADDRESS_OFFSET");
    my $chipCount = "0x01"; # default for VPD SEEPROMs
    my $devAddr = $targetObj->getAttribute($i2cConn->{DEST},"I2C_ADDRESS");
    my $engine = $targetObj->getAttribute($i2cConn->{SOURCE}, "I2C_ENGINE");
    my $i2cMasterPath = $targetObj->getAttribute($i2cConn->{SOURCE_PARENT}, "PHYS_PATH");
    my $maxMemorySizeKB = $targetObj->getAttribute($i2cConn->{DEST_PARENT}, "MEMORY_SIZE_IN_KB");
    my $port = $targetObj->getAttribute($i2cConn->{SOURCE}, "I2C_PORT");
    my $writeCycleTime = $targetObj->getAttribute($i2cConn->{DEST_PARENT}, "WRITE_CYCLE_TIME");
    my $writePageSize = $targetObj->getAttribute($i2cConn->{DEST_PARENT}, "WRITE_PAGE_SIZE");

    # Set the named EEPROM attribute, for target, with the gathered field data
    $targetObj->setAttributeField($target, $eepromName, "byteAddrOffset", $byteAddrOffset);
    $targetObj->setAttributeField($target, $eepromName, "chipCount", $chipCount);
    $targetObj->setAttributeField($target, $eepromName, "devAddr", $devAddr);
    $targetObj->setAttributeField($target, $eepromName, "engine", $engine);
    $targetObj->setAttributeField($target, $eepromName, "i2cMasterPath", $i2cMasterPath);
    $targetObj->setAttributeField($target, $eepromName, "maxMemorySizeKB", $maxMemorySizeKB);
    $targetObj->setAttributeField($target, $eepromName, "port", $port);
    $targetObj->setAttributeField($target, $eepromName, "writeCycleTime", $writeCycleTime);
    $targetObj->setAttributeField($target, $eepromName, "writePageSize", $writePageSize);
} # end setEepromAttribute

#--------------------------------------------------
# @brief Set the EEPROM_VPD_PRIMARY_INFO and FAPI_I2C_CONTROL_INFO attributes
#        for the given OCMB
#
# @detail The EEPROM_VPD_PRIMARY_INFO data is exactly the same as the DDIMM
#         parent, so will use the DDIMM parent EEPROM data to populate OCMB's
#         EEPROM fields.  The majority of the FAPI_I2C_CONTROL_INFO data is
#         equivalent to the EEPROM data, so copy the appropriate fields.
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The OCMB target
#--------------------------------------------------
sub setEepromAndFapi2AttributesForOcmb
{
    my $targetObj = shift;
    my $target    = shift;

    # Sanity check.  Make sure we are processing the correct target type.
    targetTypeSanityCheck($targetObj, $target, "OCMB_CHIP");

    # Get the DDIMM parent
    my $ddimmParent = $targetObj->getTargetParent($target);

    # Copy the parent DDIMM's EEPROM data
    my $eepromName = "EEPROM_VPD_PRIMARY_INFO";
    $targetObj->copyAttributeFields($ddimmParent, $target, $eepromName);

    # Copy some of the parent DDIMM's EEPROM data over to the FAPI2 attribute
    my $fapiName = "FAPI_I2C_CONTROL_INFO";
    $targetObj->copySrcAttributeFieldToDestAttributeField($ddimmParent, $target,
                $eepromName, $fapiName, "i2cMasterPath");
    $targetObj->copySrcAttributeFieldToDestAttributeField($ddimmParent, $target,
                $eepromName, $fapiName, "engine");
    $targetObj->copySrcAttributeFieldToDestAttributeField($ddimmParent, $target,
                $eepromName, $fapiName, "port");

    # Retrieve the I2C Address from the 'i2c-ocmb' target. Set the field
    # 'devAddr' for attribute FAPI2_I2C_CONTROL_INFO with value.
    my $devAddr = "";
    foreach my $i2cSlave (@{ $targetObj->getTargetChildren($target) })
    {
        # The OCMB has multiple i2c-slaves, so we query for instance name
        my $instanceName = $targetObj->getInstanceName($i2cSlave);
        if ($instanceName eq "i2c-ocmb")
        {
            $devAddr = $targetObj->getAttribute($i2cSlave, "I2C_ADDRESS");
            last;
        }
    }

    # If no value for the field devAddr, then this is an error.
    if ($devAddr eq "")
    {
        select()->flush(); # flush buffer before spewing out error message
        die "\nsetEepromAndFapi2AttributesForOcmb: ERROR: No child target " .
            "\"i2c-ocmb\" found for target ($target), therefore value " .
            "for field \"devAddr\" for attribute FAPI2_I2C_CONTROL_INFO " .
            "cannot be properly set.\nError";
    }

    $targetObj->setAttributeField($target, $fapiName, "devAddr", $devAddr);
} # end setEepromAndFapi2AttributesForOcmb

#--------------------------------------------------
# @brief Set the FAPI_I2C_CONTROL_INFO attribute for the given PMIC
#
# @detail The majority of the FAPI_I2C_CONTROL_INFO data is equivalent to the
#         the DDIMM parent EEPROM_VPD_PRIMARY_INFO attribute, so copy the
#         appropriate fields.
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The PMIC target
#--------------------------------------------------
sub setFapi2AttributeForPmic
{
    my $targetObj = shift;
    my $target    = shift;

    # Sanity check.  Make sure we are processing the correct target type.
    targetTypeSanityCheck($targetObj, $target, "PMIC");

    # Get the DDIMM parent
    my $ddimmParent = $targetObj->getTargetParent($target);

    # Copy some of the parent DDIMM's EEPROM data over to the FAPI2 attribute
    my $eepromName = "EEPROM_VPD_PRIMARY_INFO";
    my $fapiName = "FAPI_I2C_CONTROL_INFO";
    $targetObj->copySrcAttributeFieldToDestAttributeField($ddimmParent, $target,
                $eepromName, $fapiName, "i2cMasterPath");
    $targetObj->copySrcAttributeFieldToDestAttributeField($ddimmParent, $target,
                $eepromName, $fapiName, "engine");
    $targetObj->copySrcAttributeFieldToDestAttributeField($ddimmParent, $target,
                $eepromName, $fapiName, "port");

    # Retrieve the I2C Address from the 'unit-i2c-slave' target. Set the field
    # 'devAddr' for attribute FAPI2_I2C_CONTROL_INFO with value.
    my $devAddr = "";
    foreach my $i2cSlave (@{ $targetObj->getTargetChildren($target) })
    {
        # The PMIC has child "unit-i2c-slave" which contains the device address
        my $type = $targetObj->getTargetType($i2cSlave);
        if ($type eq "unit-i2c-slave")
        {
            $devAddr = $targetObj->getAttribute($i2cSlave, "I2C_ADDRESS");
            last;
        }
    }

    # If no value for the field devAddr, then this is an error.
    if ($devAddr eq "")
    {
        select()->flush(); # flush buffer before spewing out error message
        die "\nsetFapi2AttributeForPmic: ERROR: No child target " .
            "\"unit-i2c-slave\" found for target ($target), therefore value " .
            "for field \"devAddr\" for attribute FAPI2_I2C_CONTROL_INFO " .
            "cannot be properly set.\nError";
    }

    $targetObj->setAttributeField($target, $fapiName, "devAddr", $devAddr);
} # end setFapi2AttributeForPmic


################################################################################
# Post processing subroutines
################################################################################

#--------------------------------------------------
# @brief Post process targets of type 'SYS'
#
# @details Configure SYS attributes that can only be determined after all
#          targets have been processed.
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The SYS target
#--------------------------------------------------
sub postProcessSystem
{
    my $targetObj = shift;
    my $target    = shift;

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target has been already processed.
    my $targetType = targetTypeSanityCheck($targetObj, $target, "SYS");
    validateTargetHasBeenPreProcessed($targetObj, $target);

    $targetObj->setAttribute($target, "MAX_MCS_PER_SYSTEM",
                             $targetObj->{NUM_PROCS_PER_NODE} * $targetObj->{MAX_MCS} );
    $targetObj->setAttribute($target, "MAX_PROC_CHIPS_PER_NODE", $targetObj->{NUM_PROCS_PER_NODE});

    parseBitwise($targetObj,$target,"CDM_POLICIES");

    my $maxComputeNodes  = get_max_compute_nodes($targetObj , $target);
    $targetObj->setAttribute($target, "MAX_COMPUTE_NODES_PER_SYSTEM", $maxComputeNodes);

    #handle enumeration changes
    my $enum_val = $targetObj->getAttribute($target,"PROC_FABRIC_PUMP_MODE");
    if ( $enum_val =~ /MODE1/i)
    {
        $targetObj->setAttribute($target,"PROC_FABRIC_PUMP_MODE","CHIP_IS_NODE");
    }
    elsif ( $enum_val =~ /MODE2/i)
    {
        $targetObj->setAttribute($target,"PROC_FABRIC_PUMP_MODE","CHIP_IS_GROUP");
    }
} # end sub postProcessSystem

#--------------------------------------------------
# @brief Post process targets of type 'PROC'
#
# @details Configure PROC attributes that can only be determined after all
#          targets have been processed.
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The PROC target
#--------------------------------------------------
sub postProcessProcessor
{
    my $targetObj = shift;
    my $target    = shift;

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target has been already processed.
    my $targetType = targetTypeSanityCheck($targetObj, $target, "PROC");
    validateTargetHasBeenPreProcessed($targetObj, $target);

    # In serverwiz, processor instances are not unique because they are plugged
    # into a socket, so processor instance unique attributes are socket level.
    # The parent is guaranteed to be a module, the grandparent a socket
    my $module_target = $targetObj->getTargetParent($target);
    my $socket_target = $targetObj->getTargetParent($module_target);

    my $staticAbsLocationCode = getStaticAbsLocationCode($targetObj,$target);
    $targetObj->setAttribute($target, "STATIC_ABS_LOCATION_CODE",$staticAbsLocationCode);

    ## Copy PCIE attributes from socket
    ## Copy PBAX attributes from socket
    foreach my $attr (sort (keys
           %{ $targetObj->getTarget($socket_target)->{TARGET}->{attribute} }))
    {
        if ($attr =~ /PROC\_PCIE/)
        {
            $targetObj->copyAttribute($socket_target,$target,$attr);
        }
        elsif ($attr =~/PBAX_BRDCST_ID_VECTOR/)
        {
            $targetObj->copyAttribute($socket_target,$target,$attr);
        }
        elsif ($attr =~/PBAX_CHIPID/)
        {
            $targetObj->copyAttribute($socket_target,$target,$attr);
        }
        elsif ($attr =~/PBAX_GROUPID/)
        {
            $targetObj->copyAttribute($socket_target,$target,$attr);
        }
        elsif ($attr =~/PM_PBAX_NODEID/)
        {
            $targetObj->copyAttribute($socket_target,$target,$attr);
        }
        elsif ($attr =~/NO_APSS_PROC_POWER_VCS_VIO_WATTS/)
        {
            $targetObj->copyAttribute($socket_target,$target,$attr);
        }
    }

    # I2C arrays
    my @engine = ();
    my @port = ();
    my @slavePort = ();
    my @addr = ();
    my @speed = ();
    my @type = ();
    my @purpose = ();
    my @label = ();

    $targetObj->log($target, "Processing PROC");
    foreach my $child (@{ $targetObj->getTargetChildren($target) })
    {
        my $child_type = $targetObj->getType($child);

        $targetObj->log($target,
            "Processing PROC child: $child Type: $child_type");

        if ($child_type eq "NA" || $child_type eq "FSI")
        {
            $child_type = $targetObj->getMrwType($child);
        }

        if ($child_type eq "FSIM" || $child_type eq "FSICM")
        {
            processFsi($targetObj, $child, $target);
        }
        elsif ($child_type eq "PEC")
        {
            postProcessPec($targetObj, $child);
        }
        elsif ($child_type eq "OCC")
        {
            postProcessOcc($targetObj, $child, $target);
        }

        # Ideally this should be $child_type eq "I2C", but we need a change
        # in serverwiz and the witherspoon.xml first
        elsif (index($child,"i2c-master") != -1)
        {
            my ($i2cEngine, $i2cPort, $i2cSlavePort, $i2cAddr,
                $i2cSpeed, $i2cType, $i2cPurpose, $i2cLabel) =
                    processI2C($targetObj, $child, $target);

            # Add this I2C device's information to the proc array
            push(@engine,@$i2cEngine);
            push(@port,@$i2cPort);
            push(@slavePort,@$i2cSlavePort);
            push(@addr,@$i2cAddr);
            push(@speed,@$i2cSpeed);
            push(@type,@$i2cType);
            push(@purpose,@$i2cPurpose);
            push(@label, @$i2cLabel);

        }
    }

    # Add final I2C arrays to processor
    my $size         = scalar @engine;
    my $engine_attr  = $engine[0];
    my $port_attr    = $port[0];
    my $slave_attr   = $slavePort[0];
    my $addr_attr    = $addr[0];
    my $speed_attr   = $speed[0];
    my $type_attr    = $type[0];
    my $purpose_attr = $purpose[0];
    my $label_attr   = $label[0];

    # Parse out array to print as a string
    foreach my $n (1..($size-1))
    {
        $engine_attr    .= ",".$engine[$n];
        $port_attr      .= ",".$port[$n];
        $slave_attr     .= ",".$slavePort[$n];
        $addr_attr      .= ",".$addr[$n];
        $speed_attr     .= ",".$speed[$n];
        $type_attr      .= ",".$type[$n];
        $purpose_attr   .= ",".$purpose[$n];
        $label_attr     .= ",".$label[$n];
    }

    # Set the arrays to the corresponding attribute on the proc
    $targetObj->setAttribute($target,"HDAT_I2C_ENGINE",$engine_attr);
    $targetObj->setAttribute($target,"HDAT_I2C_MASTER_PORT",$port_attr);
    $targetObj->setAttribute($target,"HDAT_I2C_SLAVE_PORT",$slave_attr);
    $targetObj->setAttribute($target,"HDAT_I2C_ADDR",$addr_attr);
    $targetObj->setAttribute($target,"HDAT_I2C_BUS_FREQ",$speed_attr);
    $targetObj->setAttribute($target,"HDAT_I2C_DEVICE_TYPE",$type_attr);
    $targetObj->setAttribute($target,"HDAT_I2C_DEVICE_PURPOSE",$purpose_attr);
    $targetObj->setAttribute($target,"HDAT_I2C_DEVICE_LABEL", $label_attr);
    $targetObj->setAttribute($target,"HDAT_I2C_ELEMENTS",$size);

    ## update path for mvpd's and sbe's
    my $path  = $targetObj->getAttribute($target, "PHYS_PATH");
    my $model = $targetObj->getAttribute($target, "MODEL");
    $targetObj->setAttributeField($target,
        "EEPROM_VPD_PRIMARY_INFO","i2cMasterPath",$path);
    $targetObj->setAttributeField($target,
        "EEPROM_VPD_BACKUP_INFO","i2cMasterPath",$path);
    $targetObj->setAttributeField($target,
        "EEPROM_SBE_PRIMARY_INFO","i2cMasterPath",$path);
    $targetObj->setAttributeField($target,
        "EEPROM_SBE_BACKUP_INFO","i2cMasterPath",$path);

    ## need to initialize the master processor's FSI connections here
    my $proc_type = $targetObj->getAttribute($target, "PROC_MASTER_TYPE");

    if ($proc_type eq "ACTING_MASTER" )
    {
        if($targetObj->isBadAttribute($target, "FSI_MASTER_TYPE"))
        {
          $targetObj->setAttributeField($target, "FSI_OPTION_FLAGS", "reserved",
            "0");
          $targetObj->setAttribute($target, "FSI_MASTER_CHIP",    "physical:sys-0");
          $targetObj->setAttribute($target, "FSI_MASTER_PORT",    "0xFF");
          $targetObj->setAttribute($target, "ALTFSI_MASTER_CHIP", "physical:sys-0");
          $targetObj->setAttribute($target, "ALTFSI_MASTER_PORT", "0xFF");
          $targetObj->setAttribute($target, "FSI_MASTER_TYPE",    "NO_MASTER");
        }
        $targetObj->setAttribute($target, "FSI_SLAVE_CASCADE",  "0");
        $targetObj->setAttributeField($target, "SCOM_SWITCHES", "useSbeScom",
            "1");
        $targetObj->setAttributeField($target, "SCOM_SWITCHES", "useFsiScom",
            "0");
    }
    else
    {
        if($targetObj->isBadAttribute($target, "ALTFSI_MASTER_CHIP"))
        {
          $targetObj->setAttribute($target, "ALTFSI_MASTER_CHIP", "physical:sys-0");
        }
        $targetObj->setAttributeField($target, "SCOM_SWITCHES", "useSbeScom",
            "0");
        $targetObj->setAttributeField($target, "SCOM_SWITCHES", "useFsiScom",
            "1");
    }
    ## Update bus speeds
    processI2cSpeeds($targetObj,$target);

    ## these are hardcoded because code sets them properly
    $targetObj->setAttributeField($target, "SCOM_SWITCHES", "reserved",   "0");
    $targetObj->setAttributeField($target, "SCOM_SWITCHES", "useInbandScom",
        "0");
    $targetObj->setAttributeField($target, "SCOM_SWITCHES", "useXscom", "0");
    $targetObj->setAttributeField($target, "SCOM_SWITCHES", "useI2cScom","0");

    ## default effective fabric ids to match regular fabric ids
    ##  the value will be adjusted based on presence detection later
    $targetObj->setAttribute($target,
                             "PROC_EFF_FABRIC_GROUP_ID",
                             $targetObj->getAttribute($target,
                                                      "FABRIC_GROUP_ID"));
    $targetObj->setAttribute($target,
                             "PROC_EFF_FABRIC_CHIP_ID",
                             $targetObj->getAttribute($target,
                                                      "FABRIC_CHIP_ID"));


    #TODO RTC: 191762 -- Need a generic way to source FABRIC_GROUP_ID and
    #FABRIC_CHIP_ID from the MRW and select the right value in processMRW
    #based on the system configuration we are compiling for.
    my $system_config = $targetObj->{system_config};
    if ($system_config eq "w")
    {
        my $huid_str = $targetObj->getAttribute($target, "HUID");
        my $huid     = hex $huid_str;
        my $grp_id   = $targetObj->getAttribute($target,"FABRIC_GROUP_ID");
        my $chip_id  = $targetObj->getAttribute($target,"FABRIC_CHIP_ID");

        if    ($huid eq 0x50000)
        {
            $grp_id  = 0;
            $chip_id = 0;
        }
        elsif ($huid eq 0x50001)
        {
            $grp_id  = 1;
            $chip_id = 1;
        }
        elsif ($huid eq 0x50002)
        {
            $grp_id  = 0;
            $chip_id = 1;
        }
        elsif ($huid eq 0x50003)
        {
            $grp_id  = 1;
            $chip_id = 0;
        }
        else
        {
            #This is super ugly hack to make sure FABRIC_GROUP_ID and
            #FABRIC_CHIP_ID are unique in the entire system. But, it
            #doesn't matter what they are for other drawers as for
            #wrap config we only care about one drawer
            $grp_id += 1;
        }

        $targetObj->setAttribute($target,"FABRIC_GROUP_ID",$grp_id);
        $targetObj->setAttribute($target,"FABRIC_CHIP_ID",$chip_id);
        $targetObj->setAttribute($target,"PROC_EFF_FABRIC_GROUP_ID",$grp_id);
        $targetObj->setAttribute($target,"PROC_EFF_FABRIC_CHIP_ID",$chip_id);
    }

    setupMemoryMaps($targetObj,$target);

    $targetObj->setAttribute($target,
                     "PROC_MEM_TO_USE", ( $targetObj->getAttribute($target,
                     "FABRIC_GROUP_ID") << 3));

    processPowerRails ($targetObj, $target);

    # Set the MRU_ID to correct values
    {
        # Split the PROC on "-" boundaries.  That will separate the PROC numeric
        # position from the other fluff: "...power10-0" => "...power10", "0"
        my @procParts = split(/-/, $target); # array of ("...power10", "0")
        # Get the last value from array to retrieve the position (-1 in Perl means last)
        my $procPosition = $procParts[-1];

        # Set the MRU_ID to the MRU_PREFIX plus PROC position
        my $mru_prefix_id = $targetObj->{enumeration}->{MRU_PREFIX}->{PROC};
        my $mruiId = sprintf("%s%04x", $mru_prefix_id, $procPosition);

        # Set the target MRU_ID attribute
        $targetObj->setAttribute($target, "MRU_ID", $mruiId);
    }
} # end sub postProcessProcessor

#--------------------------------------------------
# @brief Post process targets of type OMI
#
# @details This method corrects the OMIC_PATH attribute.  Also calculates and
#          sets the attribute OMI_INBAND_BAR_BASE_ADDR_OFFSET.
#
# @note The majority of the OMI's attributes are done via:
#           processTargets()->processProcessorAndChildren()->
#           iterateOverChiplets()->setCommonAttrForChiplet()
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The OMI target
#--------------------------------------------------
sub postProcessOmi
{
    my $targetObj = shift;
    my $target    = shift;

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target has been already processed.
    my $targetType = targetTypeSanityCheck($targetObj, $target, "OMI");
    validateTargetHasBeenPreProcessed($targetObj, $target);

    ### Correct the OMIC_PATH
    my $omiOmicParent = $targetObj->getAttribute($target, "PHYS_PATH");

    # Remove the extraneous '/omi-#' and '/mi-#' from the 'omic path'
    $omiOmicParent =~ s/\/omi-.//;
    $omiOmicParent =~ s/\/mi-.//;

    # Replace the 'mcc' path with 'omic' because mcc has the right position and
    # don't need/want the mcc in the path.
    $omiOmicParent =~ s/mcc/omic/;

    $targetObj->setAttribute($target, "OMIC_PARENT",   $omiOmicParent);


    ### Calculate and set the attribute OMI_INBAND_BAR_BASE_ADDR_OFFSET
    ## using method hostboot/src/usr/mmio/mmio.C::mmioSetup() as a guide

    ## The offset calculations are based on the following stipulations
    ## The offset for each OMI, in an MC group, is 2GB
    ## The offset for each MC is 8GB

    ## Define some useful constants
    # The number of OMI targets to an MC target
    my $OMI_PER_MC = (getMaxInstPerProc("OMI") / getMaxInstPerProc("MC"));
    # The number of OMI targets to it's parent
    my $OMI_PER_PARENT = getMaxInstPerParent("OMI");
    # The size of a gigabyte in hex form
    use constant GB_SIZE => 0x40000000;
    # excerpt from mmio.C: "Each Memory Controller Channel (MCC) uses 8 GB of
    # Memory Mapped IO"
    use constant GB_PER_MMC => 8;
    # Each OMI will consume 2GBs of the 8GBs allocated for the MCC
    use constant GB_PER_OMI => 2;
    # The base OMI BAR address address, as defined in the simics_XXX.system.xml file
    use constant OMI_BASE_BAR_ADDRESS_OFFSET => 0x30400000000;

    # Get the OMI position using the value found in attribute FAPI_POS
    my $omiFapiPos = $targetObj->getAttribute($target,"FAPI_POS");

    # This formula is a verbatim copy of the same formula as found in
    # hostboot/src/usr/mmio/mmio.C::mmioSetup(), except without the magic numbers
    use integer;
    my $value = Math::BigInt->new(
                (($omiFapiPos / $OMI_PER_PARENT) * GB_PER_MMC * GB_SIZE) +
                (($omiFapiPos % $OMI_PER_PARENT) * GB_PER_OMI * GB_SIZE) );
    $value = OMI_BASE_BAR_ADDRESS_OFFSET + $value;

    # Put the value in hex form before setting the OMI attribute
    # OMI_INBAND_BAR_BASE_ADDR_OFFSET with value.
    $value = sprintf("0x%016X", $value);
    $targetObj->setAttribute($target, "OMI_INBAND_BAR_BASE_ADDR_OFFSET", $value);

    # Set the parent MC BAR value to the value of first OMI within the OMI group per MC
    if (($omiFapiPos % $OMI_PER_MC) eq 0)
    {
        my $parentMC = $targetObj->findParentByType($target, "MC");
        $targetObj->setAttribute($parentMC, "OMI_INBAND_BAR_BASE_ADDR_OFFSET", $value);
    }
} # end sub postProcessOmi

#--------------------------------------------------
# @brief Post process targets of type 'OMIC'
#
# @details Configure OMIC's PAUC_PARENT attribute.
#
# @note The majority of the OMI's attributes are done via:
#           processTargets()->processProcessorAndChildren()->
#           iterateOverChiplets()->setCommonAttrForChiplet()
#
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The OMIC target
#--------------------------------------------------
sub postProcessOmic
{
    my $targetObj = shift;
    my $target    = shift;

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target has been already processed.
    my $targetType = targetTypeSanityCheck($targetObj, $target, "OMIC");
    validateTargetHasBeenPreProcessed($targetObj, $target);

    # The PAUC parent uses the OMIC's physical path as a starting point
    my $omicPhysical   = $targetObj->getAttribute($target, "PHYS_PATH");

    # Create an MC to PAUC mapping
    my %mc_to_pauc_map = (  0  => "pauc-0",
                            1  => "pauc-2",
                            2  => "pauc-1",
                            3  => "pauc-3" );

    # Remove '/omic-#' and find the mc unit number
    my $paucParent  = $omicPhysical;
    $paucParent     =~ s/\/omic-.//;
    my ($mcUnit)    = ($paucParent =~ /\/mc-(\d)/);

    # Set the PAUC parent path: remove 'mc-#', append 'pauc-#'
    $paucParent     =~ s/mc-.//;
    $paucParent     = $paucParent.$mc_to_pauc_map{$mcUnit};
    $targetObj->setAttribute($target, "PAUC_PARENT", $paucParent);
} # end sub postProcessOmic

sub postProcessApss {
    my $targetObj=shift;
    my $target=shift;

    my $encTarget = $targetObj->getTargetParent($target);
    my $nodeTarget = $targetObj->getTargetParent($encTarget);
    my $systemTarget = $targetObj->getTargetParent($nodeTarget);

    my @sensors;
    my @channel_ids;
    my @channel_offsets;
    my @channel_gains;
    my @channel_grounds;
    my @gpios;

    foreach my $child (@{$targetObj->getTargetChildren($target)})
    {
        if ($targetObj->getMrwType($child) eq "APSS_SENSOR")
        {
             #TODO add PLDM specific processing here
             my $entity_id = 0;
             my $sensor_id = 0;
             my $sensor_type=0;
             my $sensor_evt=0;

            #@fixme-RTC:175309-Remove deprecated support
            my $name;
            my $channel;
            my $channel_id;
            my $channel_gain;
            my $channel_offset;
            my $channel_ground;

            if ($targetObj->getTargetType($child) eq "apss.unit-adc-generic")
            {
                #Using correct/new names for the APSS entries
                $name = $targetObj->
                  getAttribute($child,"FUNCTION_NAME");
                $channel = $targetObj->
                  getAttribute($child,"CHANNEL");
                $channel_id = $targetObj->
                  getAttribute($child,"FUNCTION_ID");
                $channel_gain = $targetObj->
                  getAttribute($child,"GAIN");

                #Channel Gain is reprsented in decimal format in the MRW
                # multiply by 1000 so it is a valid attribute value
                $channel_gain = $channel_gain * 1000;

                $channel_offset = $targetObj->
                  getAttribute($child,"OFFSET");

                #Channel Offset is reprsented in decimal format in the MRW
                # multiply by 1000 so it is a valid attribute value
                $channel_offset = $channel_offset * 1000;

#Temporarily use ADC_CHANNEL_GROUND until GND defined in MRW
                $channel_ground = $targetObj->
                  getAttribute($child,"ADC_CHANNEL_GROUND");
            }

            $name=~s/\n//g;
            $name=~s/\s+//g;
            $name=~s/\t+//g;

            my $sensor_id_str = "";
            if ($sensor_id ne "")
            {
                $sensor_id_str = sprintf("0x%02X",oct($sensor_id));
            }

            if ($channel ne "")
            {
                $sensors[$channel] = $sensor_id_str;
                $channel_ids[$channel] = $channel_id;
                $channel_grounds[$channel] = $channel_ground;
                $channel_offsets[$channel] = $channel_offset;
                $channel_gains[$channel] = $channel_gain;
            }
            my $str=sprintf(
                    " %30s | %10s |  0x%02X  | 0x%02X |    0x%02x   |" .
                    " %4s | %4d | %4d | %10s | %s\n",
                    $name,"",oct($entity_id),oct($sensor_type),
                    oct($sensor_evt),$sensor_id_str,$channel,"","",
                    $systemTarget);

            $targetObj->writeReport($str);
        } # end if ($targetObj->getMrwType($child) eq "APSS_SENSOR")
        elsif ($targetObj->getMrwType($child) eq "APSS_GPIO")
        {
            my $function_id=$targetObj->
                 getAttribute($child,"FUNCTION_ID");
            my $port=$targetObj->
                 getAttribute($child,"PORT");

            if ($port ne "")
            {
                $gpios[$port] = $function_id;
            }
        } # end elsif ($targetObj->getMrwType($child) eq "APSS_GPIO")
    } # end foreach my $child (@{$targetObj->getTargetChildren($target)})

    for (my $i=0;$i<16;$i++)
    {
        if ($sensors[$i] eq "")
        {
            $sensors[$i]="0x00";
        }
        if ($channel_ids[$i] eq "")
        {
            $channel_ids[$i]="0";
        }
        if ($channel_grounds[$i] eq "")
        {
            $channel_grounds[$i]="0";
        }
        if ($channel_gains[$i] eq "")
        {
            $channel_gains[$i]="0";
        }
        if ($channel_offsets[$i] eq "")
        {
            $channel_offsets[$i]="0";
        }
        if ($gpios[$i] eq "")
        {
            $gpios[$i]="0";
        }
    }

    $targetObj->setAttribute($systemTarget,
                 "ADC_CHANNEL_FUNC_IDS",join(',',@channel_ids));
    $targetObj->setAttribute($systemTarget,
                 "ADC_CHANNEL_SENSOR_NUMBERS",join(',',@sensors));
    $targetObj->setAttribute($systemTarget,
                 "ADC_CHANNEL_GNDS",join(',',@channel_grounds));
    $targetObj->setAttribute($systemTarget,
                 "ADC_CHANNEL_GAINS",join(',',@channel_gains));
    $targetObj->setAttribute($systemTarget,
                 "ADC_CHANNEL_OFFSETS",join(',',@channel_offsets));
    $targetObj->setAttribute($systemTarget,
                 "APSS_GPIO_PORT_PINS",join(',',@gpios));

    convertNegativeNumbers($targetObj,$systemTarget,"ADC_CHANNEL_OFFSETS",32);

} # end sub postProcessApss


sub postProcessUcd
{
    my $targetObj = shift;
    my $target    = shift;

    # Get any connection involving UCD target's child I2C slave targets
    my $i2cBuses=$targetObj->findDestConnections($target,"I2C","");
    if ($i2cBuses ne "")
    {
        foreach my $i2cBus (@{$i2cBuses->{CONN}})
        {
            # On the I2C master side of the connection, ascend one level to the
            # parent chip
            my $i2cMasterParentTarget=$i2cBus->{SOURCE_PARENT};
            my $i2cMasterParentTargetType =
                $targetObj->getType($i2cMasterParentTarget);

            # Hostboot code assumes UCDs are only connected to processors.
            if($i2cMasterParentTargetType ne "PROC")
            {
                select()->flush(); # flush buffer before spewing out error message
                die   "Model integrity error; UCD I2C connections must "
                    . "originate at a PROC target, not a "
                    . "$i2cMasterParentTargetType target.\n";
            }

            # Get the processor's physical path
            my $i2cMasterParentTargetPath = $targetObj->getAttribute(
                $i2cMasterParentTarget,"PHYS_PATH");

            # Set the UCD's I2C master path accordingly
            $targetObj->setAttributeField(
                $target, "I2C_CONTROL_INFO","i2cMasterPath",
                $i2cMasterParentTargetPath);

            # Set the UCD's I2C port and engine by accessing the
            # i2cMaster target and getting the data from it.
            my $i2cMaster = $i2cBus->{SOURCE};
            my $i2cPort = $targetObj->getAttribute($i2cMaster, "I2C_PORT");
            my $i2cEngine = $targetObj->getAttribute($i2cMaster, "I2C_ENGINE");

            $targetObj->setAttributeField($target, "I2C_CONTROL_INFO",
                                          "port", $i2cPort);

            $targetObj->setAttributeField($target, "I2C_CONTROL_INFO",
                                          "engine", $i2cEngine);

            # Set the UCD's device address by accessing the bus
            my $addr = "";
            if ($targetObj->isBusAttributeDefined(
                $i2cBus->{SOURCE},$i2cBus->{BUS_NUM},"I2C_ADDRESS"))
            {
                $addr = $targetObj->getBusAttribute($i2cBus->{SOURCE},
                    $i2cBus->{BUS_NUM}, "I2C_ADDRESS");
            }

            # If bus doesn't have I2C_ADDRESS or default value is not set,
            # then get it from i2c-slave, if defined.
            if ($addr eq "")
            {
                if (! $targetObj->isBadAttribute($i2cBus->{DEST},"I2C_ADDRESS"))
                {
                    $addr = $targetObj->getAttribute($i2cBus->{DEST},
                                                    "I2C_ADDRESS");
                }
            }

            #if the addr is still not defined, then throw an error
            if ($addr eq "")
            {
                print ("ERROR: I2C_ADDRESS is not defined for $i2cBus\n");
                $targetObj->myExit(4);
            }

            $targetObj->setAttributeField(
                $target, "I2C_CONTROL_INFO","devAddr",$addr);

            last;
        }
    }
} # end sub postProcessUcd

#  @brief Processes a TPM target
#
#  @par Detailed Description:
#      Processes a TPM target; notably determines the TPM's I2C master chip and
#      updates the associated field in the TPM_INFO attribute, especially useful
#      on multi-node or multi-TPM systems.
#
#  @param[in] $targetObj Object model reference
#  @param[in] $target    Handle of the target to process
sub postProcessTpm
{
    my $targetObj = shift;
    my $target    = shift;

    # Get any connection involving TPM target's child I2C slave targets
    my $i2cBuses=$targetObj->findDestConnections($target,"I2C","");
    if ($i2cBuses ne "")
    {
        foreach my $i2cBus (@{$i2cBuses->{CONN}})
        {
            # On the I2C master side of the connection, ascend one level to the
            # parent chip
            my $i2cMasterParentTarget=$i2cBus->{SOURCE_PARENT};
            my $i2cMasterParentTargetType =
                $targetObj->getType($i2cMasterParentTarget);

            # Hostboot code assumes CEC TPMs are only connected to processors.
            # Unless that assumption changes, this sanity check is required to
            # catch modeling errors.
            if($i2cMasterParentTargetType ne "PROC")
            {
                select()->flush(); # flush buffer before spewing out error message
                die   "Model integrity error; CEC TPM I2C connections must "
                    . "originate at a PROC target, not a "
                    . "$i2cMasterParentTargetType target.\n";
            }

            # Get its physical path
            my $i2cMasterParentTargetPath = $targetObj->getAttribute(
                $i2cMasterParentTarget,"PHYS_PATH");

            # Set the TPM's I2C master path accordingly
            $targetObj->setAttributeField(
                $target, "TPM_INFO","i2cMasterPath",
                $i2cMasterParentTargetPath);

            # All TPM I2C buses must be driven from the same I2C master, so only
            # process the first one
            last;
        }
    }
} # end sub postProcessTpm

#--------------------------------------------------
# @brief Post process targets of type IOHS
#
# @details This method sets up the SMP bus for the IOHS.
#
# @note The majority of the IOHS' attributes are done via:
#       processTargets()->processProcessorAndChildren()->
#       iterateOverChiplets()->setCommonAttrForChiplet()
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The IOHS target
#--------------------------------------------------
sub postProcessIohs
{
    my $targetObj    = shift;
    my $target       = shift;

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target has been already processed.
    my $targetType = targetTypeSanityCheck($targetObj, $target, "IOHS");
    validateTargetHasBeenPreProcessed($targetObj, $target);

    my $iohsConfigMode = $targetObj->getAttribute($target, "IOHS_CONFIG_MODE");
    if ($iohsConfigMode eq "SMPA")
    {
        # Iterate over the children looking for ABUS
        foreach my $child (@{ $targetObj->getTargetChildren($target) })
        {
            my $childType = $targetObj->getType($child);
            if ($childType eq "ABUS")
            {
                processSmpA($targetObj, $child, $target);
            }
        } # foreach my $child (@{ $targetObj->getTargetChildren($target) })
    }
    elsif ($iohsConfigMode eq "SMPX")
    {
        # Iterate over the children looking for XBUS
        foreach my $child (@{ $targetObj->getTargetChildren($target) })
        {
            my $childType = $targetObj->getType($child);
            if ($childType eq "XBUS")
            {
                processSmpX($targetObj, $child, $target);
            }
        } # foreach my $child (@{ $targetObj->getTargetChildren($target) })
    } # end if ($iohsConfigMode eq "SMPA") ... elseif ...

} # end sub postProcessIohs

#--------------------------------------------------
# @brief Set up the SMPX bus for the IOHS target
#
# @param[in] $targetObj    - The global target object blob
# @param[in] $target       - The XBUS target
# @param[in] $parentTarget - The IOHS target
#--------------------------------------------------
sub processSmpX
{
    my $targetObj     = shift;
    my $target        = shift;
    my $parentTarget  = shift;

    my $busConnection = $targetObj->getFirstConnectionBus($target);

    # Only proceed if a bus connection exists ...
    if ($busConnection ne "")
    {
        ## Ascertain the configuration
        # Create some useful variables to help w/sorting out the configuration
        my $defaultConfig = "d";
        my $wrapConfig    = "w";
        my $config = $defaultConfig;

        if ($targetObj->isBusConnBusAttrDefined($busConnection, "CONFIG_APPLY"))
        {
            $config = $targetObj->getBusConnBusAttr($busConnection, "CONFIG_APPLY");
        }

        # Validate the config value retrieved. If none retrieved or no config
        # given, then use the default value.
        if ($config eq "")
        {
            if (0 == $targetObj->{stealth_mode})
            {
                #print STDOUT "No value found for CONFIG_APPLY, default to using default value ($defaultConfig)\n";
            }
            $config = $defaultConfig;
        }

        # The CONFIG_APPLY bus attribute carries a comma separated values for each
        # X-bus connection. It can currently take the following values.
        # "w" - This connection is applicable only in wrap config
        # "d" - This connection is applicable in default config (non-wrap mode).
        # If CONFIG_APPLY does not match the system configuration we are
        # running for, then mark the peers null.
        # For example, in wrap config, CONFIG_APPLY is expected to have "w"
        # If "w" is not there, then we skip the connection and mark peers
        # as NULL
        my $systemConfig = $targetObj->{system_config};
        if (($systemConfig eq $wrapConfig && $config =~ /$wrapConfig/) ||
           ($systemConfig ne $wrapConfig && $config =~ /$defaultConfig/))
        {
            # Don't nullify the configuration attributes
            my $nullifyFlag = false;
            setCommonConfigAttributes($targetObj, $target, $parentTarget,
                                      $busConnection, $nullifyFlag);
        }
        else
        {
            # Nullify the configuration attributes
            my $nullifyFlag = true;
            setCommonConfigAttributes($targetObj, $target, $parentTarget,
                                      $busConnection, $nullifyFlag);
        } # end (($system_config eq $wrapConfig ...
    } # end if ($busConnection ne "")
} # end sub processSmpX


#--------------------------------------------------
# @brief Set up the SMPA bus for the IOHS target
#
# @param[in] $targetObj    - The global target object blob
# @param[in] $target       - The ABUS target
# @param[in] $parentTarget - The IOHS target
#--------------------------------------------------
sub processSmpA
{
    my $targetObj       = shift;
    my $target          = shift;
    my $parentTarget    = shift;

    my $busConnection = $targetObj->getFirstConnectionBus($target);

    # Only proceed if a bus connection exists ...
    if ($busConnection ne "")
    {
        ## Ascertain the configuration
        # Create some useful variables to help w/sorting out the configuration
        my $applyConfiguration = 0;
        my $twoNode = "2";
        my $threeNode = "3";
        my $fourNode = "4";
        my $config = "";

        if ($targetObj->isBusAttributeDefined($target, 0, "CONFIG_APPLY"))
        {
            $config = $targetObj->getBusAttribute($target, 0, "CONFIG_APPLY");
        }

        # The CONFIG_APPLY bus attribute carries a comma separated values
        # for each A-bus connection. For eg.,
        # "2,3,4" - This connection is applicable in 2,3 and 4 node config
        # "w" - This connection is applicable only in wrap config
        # "2" - This connection is applicable only in 2 node config
        # "4" - This connection is applicable only in 4 node config
        # The below logic looks for these values (w, 2, 3, and 4) and decides
        # whether a certain A-bus connection has to be considered or not.
        # If user has passed 2N as argument, then we consider only those
        # A-bus connections where value "2" is present in the configuration.
        my $systemConfig = $targetObj->{system_config};
        if ($systemConfig eq "2N" && $config =~ /$twoNode/)
        {
            # MRW configuration matches system configuration for a 2 node,
            # therefore apply configuration.
            $applyConfiguration = 1;
        }
        elsif ($systemConfig eq "")
        {
            # No system configuration, is MRW configuration for a 3 or 4 node system?
            # This will skip any connections specific to ONLY 2 node systems
            if($config =~ /$threeNode/ || $config =~ /$fourNode/)
            {
                # MRW configuration is for a 3 or 4 node system,
                # therefore apply configuration.
                $applyConfiguration = 1;
            }
        }
        elsif ($config =~ /$systemConfig/)
        {
            # If system configuration matches the MRW configuration, then
            # apply configuration. Ex: wrap config
            $applyConfiguration = 1;
        }
        else
        {
            # No valid configuration given via MRW nor system,
            # therefore DO NOT apply configuration.
            $applyConfiguration = 0;
        }

        # Only proceed if a valid configuration has been ascertained  ...
        if ($applyConfiguration eq 1)
        {
            my $busSrcTarget = "";
            my $busDestTarget = "";

            # Don't nullify the configuration attributes
            my $nullifyFlag = false;
            ($busSrcTarget, $busDestTarget) =
                   setCommonConfigAttributes($targetObj, $target, $parentTarget,
                                             $busConnection, $nullifyFlag);

=comment
Currently attribute EI_BUS_TX_MSBSWAP is not implemented.   Once implemented
uncomment this block and reactivate this code snippet.
            # Set bus transmit MSBSWAP for both source and destination targets
            if ($targetObj->isBusConnBusAttrDefined($busConnection, "SOURCE_TX_MSBSWAP"))
            {
                my $srcTxMsbSawp = $targetObj->getBusConnBusAttr($busConnection, "SOURCE_TX_MSBSWAP");
                $targetObj->setAttribute($busSrcTarget, "EI_BUS_TX_MSBSWAP",  $srcTxMsbSawp);
            }
            if ($targetObj->isBusConnBusAttrDefined($busConnection, "DEST_TX_MSBSWAP"))
            {
                my $destTxMsbSawp = $targetObj->getBusConnBusAttr($busConnection, "DEST_TX_MSBSWAP");
                $targetObj->setAttribute($busDestTarget, "EI_BUS_TX_MSBSWAP",  $destTxMsbSawp);
            }
=cut

            # Set the wrap config for both source and destination targets
            my $linkSet = "SET_NONE";

            if ($targetObj->isBusConnBusAttrDefined($busConnection, "MFG_WRAP_TEST_ABUS_LINKS_SET"))
            {
                $linkSet  = $targetObj->getBusConnBusAttr($busConnection, "MFG_WRAP_TEST_ABUS_LINKS_SET");
            }
            $targetObj->setAttribute($busSrcTarget,  "MFG_WRAP_TEST_ABUS_LINKS_SET", $linkSet);
            $targetObj->setAttribute($busDestTarget, "MFG_WRAP_TEST_ABUS_LINKS_SET", $linkSet);
        } # end if($applyConfiguration eq 1)
    } # end if ($busConnection ne "")
} # end sub processSmpA

#--------------------------------------------------
# @brief Set the common configuration attributes, 'PEER_TARGET', 'PEER_PATH'
#        'PEER_HUID' and 'BUS_TYPE', that are associated with configuring a bus
#
# @param[in] $targetObj     - The global target object blob
# @param[in] $target        - The BUS (ABUS/XBUS) target
# @param[in] $parentTarget  - The IOHS target - the BUS parent target
# @param[in] $busConnection - Handle to the bus connection configuration info
# @param[in] $nullifyFlag   - If false, then config attributes with valid data,
#                             else nullify the config attributes
# @return - A multiple variable return
#         $Var1 - The bus source absolute path
#         $Var2 - The bus destination absolute path
#--------------------------------------------------
sub setCommonConfigAttributes
{
    my $targetObj      = shift;
    my $target         = shift;
    my $parentTarget   = shift;
    my $busConnection  = shift;
    my $nullifyFlag    = shift;

    ## Get the source and destination paths of the target ends, do some sanity
    ## checks and expand the paths from relative to absolute.
    # Get the bus source and destination paths.
    my $busSrcPath  = $busConnection->{source_path};
    my $busDestPath = $busConnection->{dest_path};

    # Remove the ending, extraneous '/' character
    chop($busSrcPath);
    chop($busDestPath);

    # Sanity check. The parent target paths should be made up of the source
    # path. If not, then there is an issue with the MRW or Targets.pm
    if ($parentTarget !~ /$busSrcPath/)
    {
        select()->flush(); # flush buffer before spewing out error message
        die "ERROR: Target ($parentTarget) path is not comprised of the bus " .
            "source path ($busSrcPath).  Possible issue with MRW or Targets.pm ";
    }

    # Get the missing absolute path data
    my $prependingPathData = $parentTarget;
    $prependingPathData =~ s/$busSrcPath//;

    # Convert the target's relative path to an absolute path.  Targets.pm
    # can only work with targets that have absolute paths.
    my $busSrcTarget = $prependingPathData . $busSrcPath;
    my $busDestTarget = $prependingPathData . $busDestPath;

    if ( $nullifyFlag == false )
    {
        ## Get and set attributes of the target ends with valid data
        # Pre-fetch the BUS_TYPE, HUID and PHYS_PATH of the source and
        # destination targets
        my $busType = $busConnection->{bus_type};

        my $busSrcHuid = $targetObj->getAttribute($busSrcTarget, "HUID");
        my $busSrcPhysicalPath = $targetObj->getAttribute($busSrcTarget, "PHYS_PATH");

        my $busDestHuid = $targetObj->getAttribute($busDestTarget, "HUID");
        my $busDestPhysicalPath = $targetObj->getAttribute($busDestTarget, "PHYS_PATH");

        # Set attributes for the target ends
        $targetObj->setAttribute($busSrcTarget, "PEER_TARGET", $busDestPhysicalPath);
        $targetObj->setAttribute($busSrcTarget, "PEER_PATH",   $busDestPhysicalPath);
        $targetObj->setAttribute($busSrcTarget, "PEER_HUID",   $busDestHuid);
        $targetObj->setAttribute($busSrcTarget, "BUS_TYPE",    $busType);

        $targetObj->setAttribute($busDestTarget, "PEER_TARGET", $busSrcPhysicalPath);
        $targetObj->setAttribute($busDestTarget, "PEER_PATH",   $busSrcPhysicalPath);
        $targetObj->setAttribute($busDestTarget, "PEER_HUID",   $busSrcHuid);
        $targetObj->setAttribute($busDestTarget, "BUS_TYPE",    $busType);
    }
    else
    {
        # Nullify these attributes for the target ends
        $targetObj->setAttribute($busSrcTarget, "PEER_TARGET", "NULL");
        $targetObj->setAttribute($busSrcTarget, "PEER_PATH",   "physical:na");
        $targetObj->setAttribute($busSrcTarget, "PEER_HUID",   "NULL");
        $targetObj->setAttribute($busSrcTarget, "BUS_TYPE",    "NA");

        $targetObj->setAttribute($busDestTarget, "PEER_TARGET", "NULL");
        $targetObj->setAttribute($busDestTarget, "PEER_PATH",   "physical:na");
        $targetObj->setAttribute($busDestTarget, "PEER_HUID",   "NULL");
        $targetObj->setAttribute($busDestTarget, "BUS_TYPE",    "NA");
    } # end if ( $nullifyFlag == false ) ... else ...

    return ($busSrcTarget, $busDestTarget);
} # end sub setCommonConfigAttributes

sub postProcessIpmiSensors {
    my $targetObj=shift;
    my $target=shift;

    if ($targetObj->isBadAttribute($target,"IPMI_INSTANCE") ||
        $targetObj->getMrwType($target) eq "IPMI_SENSOR" ||
        $targetObj->getTargetChildren($target) eq "")
    {
        return;
    }

    my $instance=$targetObj->getAttribute($target,"IPMI_INSTANCE");
    my $name="";
    if (!$targetObj->isBadAttribute($target,"FRU_NAME"))
    {
        $name=$targetObj->getAttribute($target,"FRU_NAME");
    }
    my $fru_id="N/A";
    if (!$targetObj->isBadAttribute($target,"FRU_ID"))
    {
        $fru_id=$targetObj->getAttribute($target,"FRU_ID");
    }
    my $huid="";
    if (!$targetObj->isBadAttribute($target,"HUID"))
    {
        $huid=$targetObj->getAttribute($target,"HUID");
    }
    my @sensors;
    my %sensorIdsCnt;

    foreach my $child (@{$targetObj->getTargetChildren($target)})
    {
        if ($targetObj->getMrwType($child) eq "IPMI_SENSOR")
        {
            #RTC TODO Address with PLDM Implementation
#            my $entity_id=$targetObj->
#                 getAttribute($child,"IPMI_ENTITY_ID");
#            my $sensor_type=$targetObj->
#                 getAttribute($child,"IPMI_SENSOR_TYPE");
#            my $name_suffix=$targetObj->
#                 getAttribute($child,"IPMI_SENSOR_NAME_SUFFIX");
#            my $sensor_id=$targetObj->
#                 getAttribute($child,"IPMI_SENSOR_ID");
#            my $sensor_evt=$targetObj->
#                 getAttribute($child,"IPMI_SENSOR_READING_TYPE");

#            $name_suffix=~s/\n//g;
#            $name_suffix=~s/\s+//g;
#            $name_suffix=~s/\t+//g;
#            my $sensor_name=$name_suffix;
#            if ($name ne "")
#            {
#                $sensor_name=$name."_".$name_suffix;
#            }
#            my $attribute_name="";
#            my $s=sprintf("0x%02X%02X,0x%02X",
#                  oct($sensor_type),oct($entity_id),oct($sensor_id));
#            push(@sensors,$s);
#            my $sensor_id_str = "";
#            if ($sensor_id ne "")
#            {
#                $sensor_id_str = sprintf("0x%02X",oct($sensor_id));
#            }
#            my $str=sprintf(
#                " %30s | %10s |  0x%02X  | 0x%02X |    0x%02x   |" .
#                " %4s | %4d | %4d | %10s | %s\n",
#                $sensor_name,$name,oct($entity_id),oct($sensor_type),
#                oct($sensor_evt), $sensor_id_str,$instance,$fru_id,
#                $huid,$target);
#
#            # Check that the sensor id hasn't already been used.  Don't check
#            # blank sensor ids.
#            if (($sensor_id ne "") && (++$sensorIdsCnt{$sensor_id} >= 2)) {
#                print "ERROR: Duplicate IPMI_SENSOR_ID ($sensor_id_str)" .
#                      " found in MRW.  Sensor name is $sensor_name.\n";
#                print "$str";
#                $targetObj->myExit(3);
#            }
#
#            $targetObj->writeReport($str);
        }
    }
    for (my $i=@sensors;$i<16;$i++)
    {
        push(@sensors,"0xFFFF,0xFF");
    }
    my @sensors_sort = sort(@sensors);
    $targetObj->setAttribute($target,
                 "IPMI_SENSORS",join(',',@sensors_sort));
} # end sub postProcessIpmiSensors


#--------------------------------------------------
## FSI
##
## Finds FSI connections and creates FSI MASTER attributes at endpoint target
sub processFsi
{
    my $targetObj    = shift;
    my $target       = shift;
    my $parentTarget = shift;
    my $type         = $targetObj->getBusType($target);

    ## fsi can only have 1 connection
    my $fsi_child_conn = $targetObj->getFirstConnectionDestination($target);

    ## found something on other end
    if ($fsi_child_conn ne "")
    {
        my $fsi_link = $targetObj->getAttribute($target, "FSI_LINK");
        my $fsi_port = $targetObj->getAttribute($target, "FSI_PORT");
        my $cmfsi = $targetObj->getAttribute($target, "CMFSI");
        my $proc_path = $targetObj->getAttribute($parentTarget,"PHYS_PATH");
        my $fsi_child_target = $targetObj->getTargetParent($fsi_child_conn);
        my $flip_port         = 0;
        my $altfsiswitch      = 0;

        # If this is a proc that can be a master, then we need to set flip_port
        # attribute in FSI_OPTIONS. $flip_port tells us which FSI port to write to.
        # The default setting ( with flip_port not set) is to send instructions to port A.
        # In High End systems there are 2 master capable procs per node.
        # For the alt-master processor we need to set flip_port so that when it is master,
        # it knows to send instructions to the B port. During processMrw
        # we cannot determine which proc is master and which is the alt-master.
        # We will set flipPort on both and the later clear flipPort when we determine
        # which is actually master during hwsv init.

        #    FSP A is primary FSB B is backup
        #   |--------|        |--------|
        #   | FSP A  |        | FSP B  |
        #   |  (M)   |        |    (M) |
        #   |--------|        |--------|
        #       |
        #       V
        #   |--------|        |--------|
        #   |  (A)(B)|------->|(B) (A) |
        #   | Master |        |Alt Mast|
        #   |     (M)|        |(M)     |
        #   |--------|\       |--------|
        #          |   \
        #         /     \
        #        /       \
        #   |--------|    \   |---------|
        #   | (A) (B)|     \->|(A)  (B) |
        #   | Slave  |        |  Slave  |
        #   |        |        |         |
        #   |--------|        |---------|

        #   FSP B is primary FSB A is backup
        #
        #   |--------|        |--------|
        #   | FSP A  |        | FSP B  |
        #   |  (M)   |        |    (M) |
        #   |--------|        |--------|
        #                           |
        #                           V
        #   |--------|        |--------|
        #   |  (A)(B)|<-------|(M) (A) |
        #   | Master |       /|Alt Mast|
        #   |     (M)|      /||(B)     |
        #   |--------|     / ||--------|
        #                 /   \
        #                /     \__
        #               /         \
        #   |--------| /      |---------|
        #   |(A)  (B)|        |(A) (B)  |
        #   | Slave  |        |  Slave  |
        #   |        |        |         |
        #   |--------|        |---------|
        my $source_type = $targetObj->getType($parentTarget);
        if ( $source_type eq "PROC" )
        {
            my $proc_type = $targetObj->getAttribute($parentTarget, "PROC_MASTER_TYPE");
            if ($proc_type eq "ACTING_MASTER" || $proc_type eq "MASTER_CANDIDATE" )
            {
                my $fcid = $targetObj->getAttribute($parentTarget,"FABRIC_CHIP_ID");
                if($fcid eq 1)
                {
                  $altfsiswitch = 1;
                }
            }
        }
        my $dest_type = $targetObj->getType($fsi_child_target);
        if ($dest_type eq "PROC" )
        {
            my $proc_type = $targetObj->getAttribute($fsi_child_target, "PROC_MASTER_TYPE");
            if ($proc_type eq "ACTING_MASTER" || $proc_type eq "MASTER_CANDIDATE" )
            {
                my $fcid = $targetObj->getAttribute($fsi_child_target,"FABRIC_CHIP_ID");
                if($fcid eq 1)
                {
                  $flip_port = 1;
                }
            }
        }
        $targetObj->setFsiAttributes($fsi_child_target,
                    $type,$cmfsi,$proc_path,$fsi_link,$flip_port,$altfsiswitch);
    }
} # end sub processFsi

#--------------------------------------------------
# I2C
#
sub processI2C
{
    my $targetObj    = shift; # Top Hierarchy of targeting structure
    my $target       = shift; # I2C targetInstance
    my $parentTarget = shift; # Processor target

    # Initialize output arrays
    my @i2cEngine = ();
    my @i2cPort = ();
    my @i2cSlave = ();
    my @i2cAddr = ();
    my @i2cSpeed = ();
    my @i2cType = ();
    my @i2cPurpose = ();
    my @i2cLabel = ();

    # Step 1: get I2C_ENGINE and PORT from <targetInstance>

    my $engine = $targetObj->getAttribute($target, "I2C_ENGINE");
    if($engine eq "") {$engine = "0xFF";}

    my $port = $targetObj->getAttribute($target, "I2C_PORT");
    if($port eq "") {$port = "0xFF";}

    # Step 2: get I2C_ADDRESS and I2C_SPEED from <bus>
    #         This is different for each connection.

    my $i2cs = $targetObj->findConnections($parentTarget, "I2C","");
    if ($i2cs ne "")
    {
        # This gives all i2c connections
        foreach my $i2c (@{$i2cs->{CONN}})
        {
            # Here we are checking that the i2c source matches our target
            my $source = $i2c->{SOURCE};
            if ($source ne $target)
            {
                next;
            }

            # Most I2C devices will default the slave port, it is only valid
            # for gpio expanders.
            my $slavePort = "0xFF";
            my $purpose_str = undef;
            if ($targetObj->isBusAttributeDefined(
                    $i2c->{SOURCE},$i2c->{BUS_NUM},"I2C_PURPOSE"))
            {
                $purpose_str = $targetObj->getBusAttribute(
                               $i2c->{SOURCE},$i2c->{BUS_NUM},"I2C_PURPOSE");
            }

            if(   defined $purpose_str
               && $purpose_str ne "")
            {
                my $parent = $targetObj->getTargetParent($i2c->{DEST});
                foreach my $aTarget ( sort keys %{ $targetObj->getAllTargets()})
                {
                    if($aTarget =~ m/$parent/)
                    {
                        if ($targetObj->isBadAttribute($aTarget,"PIN_NAME"))
                        {
                            next;
                        }

                        my $pin = $targetObj->getAttribute($aTarget,
                                                           "PIN_NAME");
                        if($pin eq $purpose_str)
                        {
                            ($slavePort) = $aTarget =~ m/\-([0-9]+)$/g;
                            last;
                        }
                    }
                }
            }

            my $type_str;
            my $purpose;
            my $addr;
            my $speed;
            my $type;
            my $label;

            # For all these attributes, we need to check if they're defined,
            # and if not we set them to a default value.
            if ($targetObj->isBusAttributeDefined(
                     $i2c->{SOURCE},$i2c->{BUS_NUM},"I2C_ADDRESS"))
            {
                $addr = $targetObj->getBusAttribute(
                           $i2c->{SOURCE},$i2c->{BUS_NUM},"I2C_ADDRESS");
            }

            # If bus doesn't have I2C_ADDRESS or default value is not set,
            # then get it from i2c-slave, if defined.
            if ($addr eq "")
            {
                if (! $targetObj->isBadAttribute($i2c->{DEST},"I2C_ADDRESS") )
                {
                   $addr = $targetObj->getAttribute($i2c->{DEST},"I2C_ADDRESS");
                }
            }

            if ($addr eq "") {$addr = "0xFF";}

            if ($targetObj->isBusAttributeDefined(
                     $i2c->{SOURCE},$i2c->{BUS_NUM},"I2C_SPEED"))
            {
                $speed = HZ_PER_KHZ * $targetObj->getBusAttribute(
                           $i2c->{SOURCE},$i2c->{BUS_NUM},"I2C_SPEED");
            }

            if ($speed eq "") {$speed = "0";}

            if ($targetObj->isBusAttributeDefined(
                     $i2c->{SOURCE},$i2c->{BUS_NUM},"I2C_TYPE"))
            {
                $type_str = $targetObj->getBusAttribute(
                                $i2c->{SOURCE},$i2c->{BUS_NUM},"I2C_TYPE");
            }

            if ($type_str eq "")
            {
                $type = "0xFF";
            }
            # TPM types can vary by MODEL number
            elsif ($type_str eq "NUVOTON_TPM")
            {
                # Model values can be found in tpmddif.H and are kept in
                # sync with TPM_MODEL attribute in attribute_types_hb.xml
                my $tpm_model = $targetObj->getAttribute($i2c->{DEST_PARENT},"TPM_MODEL");
                if ($tpm_model eq 1)
                {
                    $type = $targetObj->getEnumValue("HDAT_I2C_DEVICE_TYPE",$type_str);
                }
                if ($tpm_model eq 2)
                {
                    # @TODO RTC 212201 use proper enum when <system>.xml supports it
                    #$type = $targetObj->getEnumValue("HDAT_I2C_DEVICE_TYPE","TCG_I2C_TPM");
                    $type = 0x15;
                }
            }
            else
            {
                $type = $targetObj->getEnumValue("HDAT_I2C_DEVICE_TYPE",$type_str);
            }

            if ($targetObj->isBusAttributeDefined(
                     $i2c->{SOURCE},$i2c->{BUS_NUM},"I2C_PURPOSE"))
            {
                $purpose_str = $targetObj->getBusAttribute(
                                $i2c->{SOURCE},$i2c->{BUS_NUM},"I2C_PURPOSE");
            }

            if ($purpose_str eq "")
            {
                $purpose = "0xFF";
            }
            else
            {
                $purpose = $targetObj->getEnumValue("HDAT_I2C_DEVICE_PURPOSE",
                                                    $purpose_str);
            }


            if ($targetObj->isBusAttributeDefined(
                     $i2c->{SOURCE},$i2c->{BUS_NUM},"I2C_LABEL"))
            {
                $label = $targetObj->getBusAttribute(
                           $i2c->{SOURCE},$i2c->{BUS_NUM},"I2C_LABEL");
            }

            if ($label eq "")
            {
                # For SEEPROMS:
                # <vendor>,<device type>, <data type>, <hw subsystem>
                if (($type_str eq  "SEEPROM") ||
                    ($type_str =~ m/SEEPROM_Atmel28c128/i))
                {
                    $label = "atmel,28c128,";
                }
                elsif($type_str =~ m/SEEPROM_Atmel28c256/i)
                {
                    $label = "atmel,28c256,";
                }
                if ($label ne "")
                {
                    if ($purpose_str =~ m/MODULE_VPD/)
                    {
                        $label .= "vpd,module";
                    }
                    elsif ($purpose_str =~ m/DIMM_SPD/)
                    {
                        $label .= "spd,dimm";
                    }
                    elsif ($purpose_str =~ m/PROC_MODULE_VPD/)
                    {
                        $label .= "vpd,module";
                    }
                    elsif ($purpose_str =~ m/SBE_SEEPROM/)
                    {
                        $label .= "image,sbe";
                    }
                    elsif ($purpose_str =~ m/PLANAR_VPD/)
                    {
                        $label .= "vpd,planar";
                    }
                    else
                    {
                        $label .= "unknown,unknown";
                    }
                }
                # For GPIO expanders:
                # <vendor>,<device type>,<domain>,<purpose>
                if ($label eq "")
                {
                    if ($type_str =~ m/9551/)
                    {
                        $label = "nxp,pca9551,";
                    }
                    elsif ($type_str =~ m/9552/)
                    {
                        $label = "nxp,pca9552,";
                    }
                    elsif ($type_str =~ m/9553/)
                    {
                        $label = "nxp,pca9553,";
                    }
                    elsif ($type_str =~ m/9554/)
                    {
                        $label = "nxp,pca9554,";
                    }
                    elsif ($type_str =~ m/9555/)
                    {
                        $label = "nxp,pca9555,";
                    }
                    elsif($type_str =~ m/UCX90XX/)
                    {
                        $label = "ti,ucx90xx,";
                    }

                    if ($label ne "")
                    {
                        if ($purpose_str =~ m/CABLE_CARD_PRES/)
                        {
                            $label .= "cablecard,presence";
                        }
                        elsif ($purpose_str =~ m/PCI_HOTPLUG_PGOOD/)
                        {
                            $label .= "pcie-hotplug,pgood";
                        }
                        elsif ($purpose_str =~ m/PCI_HOTPLUG_CONTROL/)
                        {
                            $label .= "pcie-hotplug,control";
                        }
                        elsif ($purpose_str =~ m/WINDOW_OPEN/)
                        {
                            $label .= "secure-boot,window-open";
                        }
                        elsif ($purpose_str =~ m/PHYSICAL_PRESENCE/)
                        {
                            $label .= "secure-boot,physical-presence";
                        }
                        else
                        {
                            $label .= "unknown,unknown";
                        }
                    }
                }

                # For TPM:
                # <vendor>,<device type>,<purpose>,<scope>
                if ($type_str eq "NUVOTON_TPM")
                {
                    # Model values can be found in tpmddif.H and are kept in
                    # sync with TPM_MODEL attribute in attribute_types_hb.xml
                    my $tpm_model = $targetObj->getAttribute($i2c->{DEST_PARENT},"TPM_MODEL");
                    if ($tpm_model eq 1)
                    {
                        $label = "nuvoton,npct601,tpm,host";
                    }
                    if ($tpm_model eq 2)
                    {
                        $label = "tcg,tpm_i2c_ptp,tpm,host";
                    }
                }

                if ($label eq "")
                {
                    $label = "unknown,unknown,unknown,unknown"
                }

                $label = '"' . $label . '"';

            } # end of filling in default label values
            elsif ($label !~ m/^\".*\"$/)
            {
                # add quotes around label
                $label = '"' . $label . '"';
            }


            # Step 3: For each connection, create an instance in the array
            #         for the DeviceInfo_t struct.
            push @i2cEngine, $engine;
            push @i2cPort, $port;
            push @i2cSlave, $slavePort;
            push @i2cAddr, $addr;
            push @i2cSpeed, $speed;
            push @i2cType, $type;
            push @i2cPurpose, $purpose;
            push @i2cLabel, $label;

        }
    }

    # Return this i2c device's information back to the processor
    return (\@i2cEngine, \@i2cPort, \@i2cSlave, \@i2cAddr,
            \@i2cSpeed, \@i2cType, \@i2cPurpose, \@i2cLabel);
} # end sub processI2C

sub processI2cSpeeds
{
    my $targetObj = shift;
    my $target    = shift;

    my @bus_speeds;
    my $bus_speed_attr=$targetObj->getAttribute($target,"I2C_BUS_SPEED_ARRAY");
    my @bus_speeds2 = split(/,/,$bus_speed_attr);

    #need to create a 4X16 array
    # This must be updated whenever I2C_BUS_SPEED_ARRAY dimensions are changed
    # We should figure out how to read the dimensions from the attribute XML
    my $i = 0;
    for my $engineIdx (0 .. 3)
    {
        for my $portIdx (0 .. 15)
        {
            $bus_speeds[$engineIdx][$portIdx] = $bus_speeds2[$i];
            $i++;
        }
    }

    my $i2cs=$targetObj->findConnections($target,"I2C","");

    if ($i2cs ne "") {
        foreach my $i2c (@{$i2cs->{CONN}}) {
            my $dest_type = $targetObj->getTargetType($i2c->{DEST_PARENT});
            my $parent_target =$targetObj->getTargetParent($i2c->{DEST_PARENT});

            if ($dest_type eq "chip-spd-device") {
                # NOOP  Thiis is being handled elsewhere in the script
                # search for setEepromAttribute to find where
            } elsif ($dest_type eq "chip-dimm-thermal-sensor") {
                 setDimmTempAttributes($targetObj, $parent_target, $i2c);
            }

            my $port=oct($targetObj->getAttribute($i2c->{SOURCE},"I2C_PORT"));
            my $engine=oct($targetObj->getAttribute(
                           $i2c->{SOURCE},"I2C_ENGINE"));
            my $bus_speed=$targetObj->getBusAttribute(
                  $i2c->{SOURCE},$i2c->{BUS_NUM},"I2C_SPEED");

            if ($bus_speed eq "" || $bus_speed==0) {
                print "ERROR: I2C bus speed not defined for $i2c->{SOURCE}\n";
                $targetObj->myExit(3);
            }

            ## choose lowest bus speed
            if ($bus_speeds[$engine][$port] eq "" ||
                  $bus_speeds[$engine][$port]==0  ||
                  $bus_speed < $bus_speeds[$engine][$port]) {
                $bus_speeds[$engine][$port] = $bus_speed;
            }
        }
    }

    #need to flatten 4x16 array
    $bus_speed_attr = "";
    for my $engineIdx (0 .. 3)
    {
        for my $portIdx (0 .. 15)
        {
            $bus_speed_attr .= $bus_speeds[$engineIdx][$portIdx] . ",";
        }
    }
    #remove last ,
    $bus_speed_attr =~ s/,$//;

    $targetObj->setAttribute($target,"I2C_BUS_SPEED_ARRAY",$bus_speed_attr);
} # end sub processI2cSpeeds

#--------------------------------------------------
## OCC
##
sub postProcessOcc
{
    my $targetObj    = shift;
    my $target       = shift;
    my $parentTarget = shift;

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target has been already processed.
    my $targetType = targetTypeSanityCheck($targetObj, $target, "OCC");
    validateTargetHasBeenPreProcessed($targetObj, $target);

    my $master_capable=0;

    my $proc_type = $targetObj->getAttribute($parentTarget, "PROC_MASTER_TYPE");

    if ($proc_type eq "ACTING_MASTER" )
    {
        $master_capable=1;
    }
    $targetObj->setAttribute($target,"OCC_MASTER_CAPABLE",$master_capable);
} # end sub postProcessOcc

#--------------------------------------------------
## PEC
##
## Creates attributes from abstract PCI attributes on bus
sub postProcessPec
{
    my $targetObj    = shift;
    my $target       = shift; # PEC

    # Some sanity checks.  Make sure we are processing the correct target type
    # and make sure the target has been already processed.
    my $targetType = targetTypeSanityCheck($targetObj, $target, "PEC");
    validateTargetHasBeenPreProcessed($targetObj, $target);

    ## process pcie config target
    ## this is a special target whose children are the different ways
    ## to configure iop/phb's

    ## Get config children
    my @lane_mask;
    $lane_mask[0][0] = "0x0000";
    $lane_mask[1][0] = "0x0000";
    $lane_mask[2][0] = "0x0000";
    $lane_mask[3][0] = "0x0000";

    my $pec_iop_swap = 0;
    my $bitshift_const = 0;
    my $pec_num = $targetObj->getAttribute
                      ($target, "CHIP_UNIT");

    my $chipletIdValue = sprintf("0x%x",
                                 ( getParentPervasiveOffset($targetType)
                                   + $pec_num));

    $targetObj->setAttribute( $target, "CHIPLET_ID", $chipletIdValue);

    foreach my $pec_config_child (@{ $targetObj->getTargetChildren($target) })
    {
        my $phb_counter = 0;
        foreach my $phb_child (@{ $targetObj->getTargetChildren
                                                  ($pec_config_child) })
        {
            foreach my $phb_config_child (@{ $targetObj->getTargetChildren
                                                             ($phb_child) })
            {
                my $num_connections = $targetObj->getNumConnections
                                                      ($phb_config_child);
                if ($num_connections > 0)
                {
                    # We have a PHB connection
                    # We need to create the PEC attributes
                    my $phb_num = $targetObj->getAttribute
                                      ($phb_config_child, "PHB_NUM");

                    # Get lane group and set lane masks
                    my $lane_group = $targetObj->getAttribute
                                      ($phb_config_child, "PCIE_LANE_GROUP");

                    # Set up Lane Swap attribute
                    # Get attribute that says if lane swap is set up for this
                    # bus. Taken as a 1 or 0 (on or off)
                    # Lane Reversal = swapped lanes
                    my $lane_swap = $targetObj->getBusAttribute
                            ($phb_config_child, 0, "LANE_REVERSAL");

                    # Lane swap comes out as "00" or "01" - so add 0 so it
                    # converts to an integer to evaluate.
                    my $lane_swap_int = $lane_swap + 0;

                    # The PROC_PCIE_IOP_SWAP attribute is PEC specific. The
                    # right most bit represents the highest numbered PHB in
                    # the PEC. e.g. for PEC2, bit 7 represents PHB5 while bit
                    # 5 represents PHB3. A value of 5 (00000101) represents
                    # both PHB3 and 5 having swap set.

                    # Because of the ordering of how we process PHB's and the
                    # different number of PHB's in each PEC we have to bitshift
                    # by a different number for each PHB in each PEC.
                    if ($lane_swap_int)
                    {
                        if ($pec_num eq 0)
                        {
                            # This number is not simply the PEC unit number,
                            # but the number of PHB's in each PEC.
                            $bitshift_const = 0;
                        }
                        elsif ($pec_num eq 1)
                        {
                            $bitshift_const = 1;
                        }
                        elsif ($pec_num eq 2)
                        {
                            $bitshift_const = 2;
                        }
                        else
                        {
                            select()->flush(); # flush buffer before spewing out error message
                            die "Invalid PEC Chip unit number for target $target";
                        }

                        # The bitshift number is the absoulte value of the phb
                        # counter subtracted from the bitshift_const for this
                        # pec. For PHB 3, this abs(0-2), giving a bitshift of 2
                        # and filling in the correct bit in IOP_SWAP (5).
                        my $bitshift = abs($phb_counter - $bitshift_const);

                        $pec_iop_swap |= 1 << $bitshift;
                    }

                    my $pcie_bifurcated = "0";
                    if ($targetObj->isBusAttributeDefined($phb_config_child, 0, "PCIE_BIFURCATED")) {
                        $pcie_bifurcated = $targetObj->getBusAttribute
                                ($phb_config_child, 0, "PCIE_BIFURCATED");
                    }
                    # Set the lane swap for the PEC. If we find more swaps as
                    # we process the other PCI busses then we will overwrite
                    # the overall swap value with the newly computed one.
                    if ($pcie_bifurcated eq "1") {
                        $targetObj->setAttribute($target,
                            "PEC_PCIE_IOP_SWAP_BIFURCATED", $pec_iop_swap);
                    } else {
                        $targetObj->setAttribute($target,
                            "PEC_PCIE_IOP_SWAP_NON_BIFURCATED", $pec_iop_swap);
                        $targetObj->setAttribute($target,
                            "PROC_PCIE_IOP_SWAP", $pec_iop_swap);
                    }

                    $lane_mask[$lane_group][0] =
                        $targetObj->getAttribute
                            ($phb_config_child, "PCIE_LANE_MASK");

                    my $lane_mask_attr = sprintf("%s,%s,%s,%s",
                        $lane_mask[0][0], $lane_mask[1][0],
                        $lane_mask[2][0], $lane_mask[3][0]);

                    if ($pcie_bifurcated eq "1") {
                        $targetObj->setAttribute($target,
                            "PEC_PCIE_LANE_MASK_BIFURCATED", $lane_mask_attr);
                    } else {
                        $targetObj->setAttribute($target, "PROC_PCIE_LANE_MASK",
                            $lane_mask_attr);
                        $targetObj->setAttribute($target,
                            "PEC_PCIE_LANE_MASK_NON_BIFURCATED", $lane_mask_attr);
                    }

                    # Only compute the HDAT attributes if they are available
                    # and have default values
                    if (!($targetObj->isBadAttribute($phb_config_child,
                                                        "ENABLE_LSI")))
                    {
                        # Get capabilites, and bit shift them correctly
                        # Set the CAPABILITES attribute for evey PHB
                        my $lsiSupport = $targetObj->getAttribute
                                         ($phb_config_child, "ENABLE_LSI");
                        my $capiSupport = ($targetObj->getAttribute
                                      ($phb_config_child, "ENABLE_CAPI")) << 1;
                        my $cableCardSupport = ($targetObj->getAttribute
                                 ($phb_config_child, "ENABLE_CABLECARD")) << 2;
                        my $hotPlugSupport = ($targetObj->getAttribute
                                   ($phb_config_child, "ENABLE_HOTPLUG")) << 3;
                        my $sriovSupport = ($targetObj->getAttribute
                                     ($phb_config_child, "ENABLE_SRIOV")) << 4;
                        my $elLocoSupport = ($targetObj->getAttribute
                                    ($phb_config_child, "ENABLE_ELLOCO")) << 5;
                        my $nvLinkSupport = ($targetObj->getAttribute
                                    ($phb_config_child, "ENABLE_NVLINK")) << 6;
                        my $capabilites = sprintf("0x%X", ($nvLinkSupport |
                            $elLocoSupport | $sriovSupport | $hotPlugSupport |
                            $cableCardSupport | $capiSupport | $lsiSupport));


                        $targetObj->setAttribute($phb_child, "PCIE_CAPABILITES",
                            $capabilites);

                        # Set MGC_LOAD_SOURCE for every PHB
                        my $mgc_load_source = $targetObj->getAttribute
                           ($phb_config_child, "MGC_LOAD_SOURCE");

                        $targetObj->setAttribute($phb_child, "MGC_LOAD_SOURCE",
                            $mgc_load_source);

                        # Find if this PHB has a pcieslot connection
                        my $pcieBusConnection =
                            $targetObj->findConnections($phb_child,"PCIE","");

                        # Inspect the connection and set appropriate attributes
                        foreach my $pcieBus (@{$pcieBusConnection->{CONN}})
                        {
                            # Check if destination is a switch(PEX) or built in
                            # device(USB) and set entry type attribute
                            my $destTargetType = $targetObj->getTargetType
                                ($pcieBus->{DEST_PARENT});
                            if ($destTargetType eq "chip-PEX8725")
                            {
                                # Destination is a switch upleg. Set entry type
                                # that corresponds to switch upleg.
                                $targetObj->setAttribute($phb_child,
                                    "ENTRY_TYPE","0x01");

                                # Set Station ID (only valid for switch upleg)
                                my $stationId = $targetObj->getAttribute
                                   ($pcieBus->{DEST}, "STATION");

                                $targetObj->setAttribute($phb_child,
                                    "STATION_ID",$stationId);
                                # Set device and vendor ID from the switch
                                my $vendorId = $targetObj->getAttribute
                                   ($pcieBus->{DEST_PARENT}, "VENDOR_ID");
                                my $deviceId = $targetObj->getAttribute
                                   ($pcieBus->{DEST_PARENT}, "DEVICE_ID");
                                $targetObj->setAttribute($phb_child,
                                    "VENDOR_ID",$vendorId);
                                $targetObj->setAttribute($phb_child,
                                    "DEVICE_ID",$deviceId);
                            }
                            elsif ($destTargetType eq "chip-TUSB7340")
                            {
                                # Destination is a built in device. Set entry
                                # type that corresponds to built in device
                                $targetObj->setAttribute($phb_child,
                                    "ENTRY_TYPE","0x03");
                                # Set device and vendor ID from the device
                                my $vendorId = $targetObj->getAttribute
                                   ($pcieBus->{DEST_PARENT}, "VENDOR_ID");
                                my $deviceId = $targetObj->getAttribute
                                   ($pcieBus->{DEST_PARENT}, "DEVICE_ID");
                                $targetObj->setAttribute($phb_child,
                                    "VENDOR_ID",$vendorId);
                                $targetObj->setAttribute($phb_child,
                                    "DEVICE_ID",$deviceId);
                            }

                            # If the source is a PEX chip, its a switch downleg
                            # Set entry type accordingly
                            my $sourceTargetType = $targetObj->getTargetType
                                ($pcieBus->{SOURCE_PARENT});
                            if ($sourceTargetType eq "chip-PEX8725")
                            {
                                # Destination is a switch downleg.
                                $targetObj->setAttribute($phb_child,
                                    "ENTRY_TYPE","0x02");

                                # Set Ports which this downleg switch connects
                                # to. Only valid for switch downleg
                                my $portId = $targetObj->getAttribute
                                   ($pcieBus->{DEST}, "PORT");

                                $targetObj->setAttribute($phb_child, "PORT_ID",
                                    $portId);

                                # Set device and vendor ID from the device
                                my $vendorId = $targetObj->getAttribute
                                   ($pcieBus->{SOURCE_PARENT}, "VENDOR_ID");
                                my $deviceId = $targetObj->getAttribute
                                   ($pcieBus->{SOURCE_PARENT}, "DEVICE_ID");
                                $targetObj->setAttribute($phb_child,
                                    "VENDOR_ID",$vendorId);
                                $targetObj->setAttribute($phb_child,
                                    "DEVICE_ID",$deviceId);
                            }

                            # Get the parent of the DEST_PARENT, and chek its
                            # instance type
                            my $parent_target =
                              $targetObj->getTargetParent($pcieBus->{DEST_PARENT});
                            my $parentTargetType =
                                $targetObj->getTargetType($parent_target);
                            if ($parentTargetType eq "slot-pcieslot-generic")
                            {
                                # Set these attributes only if we are in a pcie
                                # slot connection
                                my $hddw_order = $targetObj->getAttribute
                                    ($parent_target, "HDDW_ORDER");
                                my $slot_index = $targetObj->getAttribute
                                    ($parent_target, "SLOT_INDEX");
                                my $slot_name = $targetObj->getAttribute
                                    ($parent_target, "SLOT_NAME");
                                my $mmio_size_32 = $targetObj->getAttribute
                                    ($parent_target, "32BIT_MMIO_SIZE");
                                my $mmio_size_64 = $targetObj->getAttribute
                                    ($parent_target, "64BIT_MMIO_SIZE");
                                my $dma_size_32 = $targetObj->getAttribute
                                    ($parent_target, "32BIT_DMA_SIZE");
                                my $dma_size_64 = $targetObj->getAttribute
                                    ($parent_target, "64BIT_DMA_SIZE");

                                $targetObj->setAttribute($phb_child, "HDDW_ORDER",
                                    $hddw_order);
                                $targetObj->setAttribute($phb_child, "SLOT_INDEX",
                                    $slot_index);
                                $targetObj->setAttribute($phb_child, "SLOT_NAME",
                                    $slot_name);
                                $targetObj->setAttribute($phb_child,
                                    "PCIE_32BIT_MMIO_SIZE", $mmio_size_32);
                                $targetObj->setAttribute($phb_child,
                                    "PCIE_64BIT_MMIO_SIZE", $mmio_size_64);
                                $targetObj->setAttribute($phb_child,
                                    "PCIE_32BIT_DMA_SIZE", $dma_size_32);
                                $targetObj->setAttribute($phb_child,
                                    "PCIE_64BIT_DMA_SIZE", $dma_size_64);
                                $targetObj->setAttribute($phb_child,
                                    "ENTRY_FEATURES", "0x0001");

                                # Only set MAX_POWER if it exisits in the system
                                # xml. TODO to remove this check when system xml
                                # is upated: RTC:175319
                                if (!($targetObj->isBadAttribute
                                    ($parent_target,"MAX_POWER")))
                                {
                                    my $maxSlotPower = $targetObj->getAttribute
                                    ($parent_target, "MAX_POWER");
                                    $targetObj->setAttribute($phb_child,
                                        "MAX_POWER",$maxSlotPower);
                                }

                            }
                            else
                            {
                                # Set these attributes only for non-pcie slot
                                # connections
                                $targetObj->setAttribute($phb_child,
                                    "ENTRY_FEATURES", "0x0002");
                            }
                        }
                    }
                } # Found connection
            } # PHB bus loop

            $phb_counter = $phb_counter + 1;

        } # PHB loop
    } # PEC config loop
} # end sub postProcessPec

sub processPowerRails
{
    my $targetObj = shift;
    my $target    = shift;

    #Example of how system xml is getting parsed into data structures here
    #and eventually into the attribute
    #
    #System XML has this:
    #<bus>
    #    <bus_id>vrm3-connector-22/vrm-type3-10/35219-3-8/IR35219_special.vout-0 => fcdimm-connector-69/fcdimm-14/membuf-0/MemIO</bus_id>
    #    <bus_type>POWER</bus_type>
    #    <cable>no</cable>
    #    <source_path>vrm3-connector-22/vrm-type3-10/35219-3-8/</source_path>
    #    <source_target>IR35219_special.vout-0</source_target>
    #    <dest_path>fcdimm-connector-69/fcdimm-14/membuf-0/</dest_path>
    #    <dest_target>MemIO</dest_target>
    #    <bus_attribute>
    #            <id>CLASS</id>
    #    <default>BUS</default>
    #    </bus_attribute>
    #</bus>
    #
    #each of the connection comes up like this (this is $rail variable)
    # 'BUS_NUM' => 0,
    # 'DEST_PARENT' => '/sys/node-4/calliope-1/fcdimm-connector-69/fcdimm-14/membuf-0',
    # 'DEST' => '/sys/node-4/calliope-1/fcdimm-connector-69/fcdimm-14/membuf-0/MemIO',
    # 'SOURCE_PARENT' => '/sys/node-4/calliope-1/vrm3-connector-22/vrm-type3-10/35219-3-8',
    # 'SOURCE' => '/sys/node-4/calliope-1/vrm3-connector-22/vrm-type3-10/35219-3-8/IR35219_special.vout-0'
    #
    #So, for 'SOURCE' target, we walk up the hierarchy till we get to
    #vrm3-connector-22 as that is the first target in the hierarchy that
    #is unique per instance of a given volate rail. We get vrm connector's
    #POSITION and set it as the ID for that rail.
    #
    #The 'DEST' target also has an attribute called "RAIL_NAME" that we can use
    #to figure out which rail we are working with. But, for rails that are
    #common between proc and centaur have "Cent" or "Mem" as a prefix.
    #
    my $rails=$targetObj->findDestConnections($target,"POWER","");
    if ($rails ne "")
    {
        foreach my $rail (@{$rails->{CONN}})
        {
            my $rail_dest = $rail->{DEST};
            my $rail_src  = $rail->{SOURCE};
            my $rail_name = $targetObj->getAttribute($rail_dest, "RAIL_NAME");
            #Need to get the connector's position and set the ID to that
            #As it is unique for every new connection in the MRW
            my $rail_connector =  $targetObj->getTargetParent( #VRM connector
                                 ($targetObj->getTargetParent #VRM type
                                 ($targetObj->getTargetParent($rail_src))));


            my $position = $targetObj->getAttribute($rail_connector,"POSITION");
            my $rail_attr_id =
                ($targetObj->getAttribute($target, "TYPE") eq "PROC") ?
                "NEST_" : "";

            #The rails that are common between proc and centaur have a "Cent"
            #prefix in the system xml. We don't care for "Cent" in our attribute
            #as it is scoped to the right target. But, for VIO, we decided to
            #use MemIO rather than CentIO. The attribute is named as VIO_ID.
            $rail_name =~ s/Cent//g;
            $rail_name =~ s/Mem/V/g;
            $rail_attr_id .= $rail_name . "_ID";

            $targetObj->setAttribute($target, $rail_attr_id, $position);
        }
    }
} # end sub processPowerRails


################################################################################
# Subroutines that support the post processing subroutines
################################################################################

#--------------------------------------------------
# @brief This will set the PAU's ordinal ID.
#
# @details For a given PROC, PAU1 and PAU2 (0-based) are not used.
#          Normal calculation is done with the position of the PAU.  With PAU1
#          and PAU2 not being used, the position is not sequential but the
#          ordinal ID's for the used PAUs must be sequential.  There
#          are gaps in the position which must be realigned to get a contiguous
#          integer sequence.
#
# @details Need to take a sequence such as:
#          0, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 15
#          transform to:
#          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
#          The sequence deviates after every 1st PAU in a given PROC.
#          To find those numbers, look for every number that is a product
#          of the maximum number of PAUs per PROC and the PROCs position.
#          Then realign those numbers.
#
# @param [in] $targetObj - The global target object.
# @param [in] $pauTarget - a target of type PAU
#--------------------------------------------------
sub setPauOrdinalId
{
    my $targetObj = shift;
    my $pauTarget = shift;

    # Verify that target type is of type PAU
    my $targetType = $targetObj->getType($pauTarget);
    if ($targetType ne "PAU")
    {
        select()->flush(); # flush buffer before spewing out error message
        die "setPauOrdinalId: ERROR: Target type must be \"PAU\" not " .
            "\"$targetType\". Error";
    }

    # Need to get the PROC for this PAU target
    my $procParent = $targetObj->findParentByType($pauTarget, "PROC");

    # Get the position of the PROC which is used to calculate the ORDINAL_ID
    my $procPosition = $targetObj->getAttribute($procParent, "POSITION");

    # Get the current ORDINAL_ID of the PAU, which will have numerical gaps.
    my $targetOrdinalId = $targetObj->getAttribute($pauTarget, "ORDINAL_ID");

    # Gaps begin on the 2nd ordinal id (1 for 0-based) for every proc.
    my $maxInst = getMaxInstPerProc($targetType);
    if ($targetOrdinalId >=
        (($procPosition * $maxInst) + 1) )
    {
        $targetOrdinalId = $targetOrdinalId - (($procPosition + 1) * 2);
    }
    elsif ($targetOrdinalId > 0)  # Do not process 0
    {
        $targetOrdinalId = $targetOrdinalId - ($procPosition * 2);
    }

    $targetObj->setAttribute($pauTarget, "ORDINAL_ID", $targetOrdinalId);
}

#--------------------------------------------------
# @brief Set up memory maps for certain attributes of the PROCS
#--------------------------------------------------
sub setupMemoryMaps
{
    my $targetObj = shift;
    my $target = shift;

    # Keep track of which topology IDs have been used
    my $topoId = getTopologyId($targetObj, $target);
    $targetObj->{TOPOLOGY}->{$topoId}++;

    # Get the topology index
    my $topologyIndex = getTopologyIndex($targetObj, $target);

    # P10 has a defined memory map for all configurations,
    # these are the base addresses for topology ID 0 (group0-chip0).
    my %bars=(  "FSP_BASE_ADDR"             => 0x0006030100000000,
                "PSI_BRIDGE_BASE_ADDR"      => 0x0006030203000000);

    #Note - Not including XSCOM_BASE_ADDRESS and LPC_BUS_ADDR in here
    # because Hostboot code itself writes those on every boot
    if (!$targetObj->isBadAttribute($target,"XSCOM_BASE_ADDRESS") )
    {
        $targetObj->deleteAttribute($target,"XSCOM_BASE_ADDRESS");
    }
    if (!$targetObj->isBadAttribute($target,"LPC_BUS_ADDR") )
    {
        $targetObj->deleteAttribute($target,"LPC_BUS_ADDR");
    }

    # The topology index resides in bits 15:19 of the P10 memory map.
    # This offset, when multiplied to the index, will put the index in the
    # correct bits of the memory map.
    my $topologyIndexOffset = 0x0000100000000000;

    # Add the topology index to the bar base memory
    foreach my $bar (keys %bars)
    {
        my $base = Math::BigInt->new($bars{$bar});

        # Add the topology index (multiplied out to the correct position)
        # to the base.
        my $value=sprintf("0x%016s",substr(($base +
                          ($topologyIndexOffset*$topologyIndex))->as_hex(),2));
        # Set the bar of the target to calculated value
        $targetObj->setAttribute($target,$bar,$value);
    }
} # end setupMemoryMaps

#--------------------------------------------------
# @brief Retrieve the fabric topology mode
#
# @details The fabric topology mode, attribute PROC_FABRIC_TOPOLOGY_MODE,
#          is an attribute of the top level target (sys-0), but retrieving
#          the value from the attribute returns a string (MODE0 or MODE1).
#          This string is used to get the actual value, tied to that mode,
#          within the enumeration types.
#
# @param[in] $targetObj - The global target object, needed to get topology mode
#
# @return the numerical value of the topology mode in base 10
#--------------------------------------------------
sub getTopologyMode
{
    my $targetObj = shift;

    use constant TOPOLOGY_MODE_ATTRIBUTE => "PROC_FABRIC_TOPOLOGY_MODE";

    # Get topology mode from top level target
    # Need to prepend "/" to the returned top level target because targets
    # are mapped slightly different in the TARGETS hash vs the xml hash.
    my $topologoyMode = $targetObj->getAttribute("/".$targetObj->{TOP_LEVEL},
                                                 TOPOLOGY_MODE_ATTRIBUTE);

    # Return the value of the mode as defined in
    # enumeration type PROC_FABRIC_TOPOLOGY_MODE
    # Convert the value from hex to base 10
    return hex($targetObj->{xml}->{enumerationTypes}->{enumerationType}
                      ->{PROC_FABRIC_TOPOLOGY_MODE}
                      ->{enumerator}->{$topologoyMode}->{value});
}

#--------------------------------------------------
# @brief Convert the topology ID to a topology index.
#
# @details  The topology ID is a 4 bit value that will be converted to a 5 bit
#           topology index. The topology index is an index into the topology
#           table.
#           The conversion method depends on the topology mode.
#                Mode      ID      index
#               MODE 0 => GGGC --> GGG0C
#               MODE 1 => GGCC --> GG0CC
#
# @param[in] $topologyId - The topology ID to convert to an index
# @param[in] $topologyMode - The topology mode that determines the conversion
#                            method. Needs to be a base 10 numeral value.
#
# @return a toplogy index, that is a base 10 numeral value.
#--------------------------------------------------
sub convertTopologyIdToIndex
{
    my $topologyId = shift;
    my $topologyMode = shift;

    use constant TOPOLOGY_MODE_1 => 1;

    # Assume topology mode 0 (GGGC -> GGG0C)
    my $groupMask = 0xE; # Use 0xE, 1110b, to extract 'GGG' from 'GGGC'
    my $chipMask = 0x1;  # Use 0x1, 0001b, to extract 'C' from 'GGGC'

    # If topology mode 1 (GGCC -> GG0CC)
    if (TOPOLOGY_MODE_1 == $topologyMode)
    {
        $groupMask = 0xC; # Use 0xC, 1100b, to extract 'GG' from 'GGCC'
        $chipMask = 0x3;  # Use 0x3, 0011b, to extract 'CC' from 'GGCC'
    }

    # Set topology index to topology ID before doing conversion
    my $topologyIndex = $topologyId;

    ## Turn the 4 bit topology ID into a 5 bit index
    ## convert GGGC to GGG0C
    ##      OR GGCC to GG0CC
    # If group mask equal to 0xE (mode 0) then extract 'GGG' from 'GGGC':
    #  1) GGGC & 0xE (1110b) returns GGG0 then shift left (<< 1) to get GGG00
    #  2) extract C from GGGC: GGGC & 0x1 (0001b) returns C
    # If group mask equal to 0xC (mode 1) then extract 'GG' from 'GGCC':
    #  1) GGCC & 0xC (1100b) returns GG00 then shift left (<< 1) to get GG000
    #  2) extract CC from GGCC: GGCC & 0x3 (0011b) returns CC
    # Bitwise 'OR' 1 and 2 together to produce a 5 bit index value: GGG0C OR GG0CC
    #    Index     =                  1                  'OR'               2
    $topologyIndex = (($topologyIndex & $groupMask) << 1) | ($topologyIndex & $chipMask);

    return ($topologyIndex);
}

#--------------------------------------------------
# @brief Get the topology ID from processor
#
#
# @param[in] $targetObj - The global target object, needed to get topology mode
# @param[in] $processorTarget - The processor target, has the attribute topology ID
#
# @return topology ID, that is a base 10 numeral value.
#--------------------------------------------------
sub getTopologyId
{
    my $targetObj = shift;
    my $processorTarget = shift;

    use constant TOPOLOGY_ID_ATTRIBUTE => "PROC_FABRIC_TOPOLOGY_ID";

    # Get the topology ID from the processor.
    # Convert hex value to base 10 numerical value
    return (hex($targetObj->getAttribute($processorTarget,
                                         TOPOLOGY_ID_ATTRIBUTE) ));
}

#--------------------------------------------------
# @brief Get the topology index, an index into the topology table.
#
# @details The topology index needs to be calculated using the topology mode
#          and the topology ID.  @see convertTopologyIdToIndex for
#          more details
#
# @param[in] $targetObj - The global target object, needed to get topology mode
# @param[in] $processorTarget - The processor target has the attribute topology ID
#
# @return a topology index, that is base 10 numeral value.
#--------------------------------------------------
sub getTopologyIndex
{
    my $targetObj = shift;
    my $processorTarget = shift;

    # Get the topology mode: MODE 0 (0) or MODE 1 (1)
    my $topologyMode = getTopologyMode($targetObj);

    # Get the topology ID from the processor.
    my $topologyId = getTopologyId($targetObj, $processorTarget);

    # Convert the topology ID to a topology index. The conversion method is
    # based on the topology mode.
    return (convertTopologyIdToIndex($topologyId, $topologyMode));
}

################################################################################
# General supporting subroutines
################################################################################
#--------------------------------------------------
# @brief Will check the given target type against the given expected type.
#        If the target's type is not the expected type, then will exit stating so.
#
# @param[in] $targetObj    - The global target object blob
# @param[in] $target       - The target
# @param[in] $expectedType - The expected type of the target
#--------------------------------------------------
sub targetTypeSanityCheck
{
    my $targetObj    = shift;
    my $target       = shift;
    my $expectedType = shift;

    # Sanity check, make sure caller passed in the target type that is expected.
    my $type = $targetObj->getType($target);
    if ($type ne $expectedType)
    {
        select()->flush(); # flush buffer before spewing out error message
        confess("\ntargetTypeSanityCheck: ERROR: Target \"$target\" is " .
                "of type \"$type\" expected type \"$expectedType\". Error");
    }

    return $type;
}

#--------------------------------------------------
# @brief Will create and set attribute 'HB_TARGET_PROCESSED' to 1 for target.
#
# @details This is a temporary attribute that can be check to determine if
#          been processed.  There attribute must be removed.  It is temporary
#          and only used for book keeping
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The target to set attribute for
#--------------------------------------------------
sub markTargetAsProcessed
{
    my $targetObj    = shift;
    my $target       = shift;
    $targetObj->setAttribute($target, "HB_TARGET_PROCESSED", 1);
}

#--------------------------------------------------
# @brief Will validate that the parent has been previously processed
#
# @details Will validate that the parent has been previously processed and if
#          so will return 1 signifying success.  If the parent has not been
#          previously processed then will exit with an error message.  This
#          method is useful when needing to verify that parent has been
#          previously processed.
#
# @param[in] $targetObj - The global target object blob
# @param[in] $child     - The child target to check parent of
# @param[in][optional] $parentType - The parent's type in lineage to match
# @return 1 if successful, else exit script with error message
#--------------------------------------------------
sub validateParentHasBeenProcessed
{
    my $targetObj = shift;
    my $child     = shift;
    my $parentType = shift;

    # If caller supplied the type of parent to find, then use that parent
    # else use the parent immediately one behind
    my $parent = "";
    if ($parentType)
    {
        $parent = $targetObj->findParentByType($child, $parentType);
    }
    else
    {
        $parent = $targetObj->getTargetParent($child);
    }

    # Error out if the parent has not been processed
    if ( !($targetObj->doesAttributeExistForTarget($parent, "HB_TARGET_PROCESSED")) ||
         !($targetObj->getAttribute($parent, "HB_TARGET_PROCESSED") == 1) )
    {
        select()->flush(); # flush buffer before spewing out error message
        confess("\nvalidateParentHasBeenProcessed: ERROR: Target of type \"" .
                $targetObj->getType($parent) . "\" must be processed before " .
                "processing target of type \"" .
                $targetObj->getType($child) .
                "\". Error");
    }

    return 1;
}

#--------------------------------------------------
# @brief Will validate that the given target has been previously processed
#
# @details Will validate that the given target has been previously processed and
#          if so, will return 1 signifying success.  If given target has not been
#          previously processed then will exit with an error message.  This
#          method is useful when needing to verify that the target has been
#          previously processed.
#
# @param[in] $targetObj - The global target object blob
# @param[in] $target    - The target to check if it has been processed
# @param[in][optional] $parentType - The parent's type in lineage to match
# @return 1 if successful, else exit script with error message
#--------------------------------------------------
sub validateTargetHasBeenPreProcessed($targetObj, $target)
{
    my $targetObj  = shift;
    my $target     = shift;

    # Error out if the parent has not been processed
    if ( !($targetObj->doesAttributeExistForTarget($target, "HB_TARGET_PROCESSED")) ||
         !($targetObj->getAttribute($target, "HB_TARGET_PROCESSED") == 1) )
    {
        select()->flush(); # flush buffer before spewing out error message
        confess("\validateTargetHasBeenPreProcessed: ERROR: Target of type \"" .
                $targetObj->getType($target) . "\" must be pre processed before " .
                "post processing this target. Error");
    }

    return 1;
}

#--------------------------------------------------
#  @brief Returns whether system has multiple possible TPMs or not
#
#  @par Detailed Description:
#      Returns whether system has multiple possible TPMs or not.
#      The MRW parser activates more complicated I2C master detection logic when
#      a system blueprint defines more than one TPM, in order to avoid having to
#      fix other non-compliant workbooks.  If every workbook is determined to
#      model the TPM and its I2C connection properly, this special case can be
#      removed.
#
#  @param[in] $targetsRef Reference to array of targets in the system
#  @retval 0 System does not have multiple possible TPMs
#  @retval 1 System has multiple possible TPMs
#
#  @TODO RTC: 189374 Remove API when all platforms' MRW supports dynamically
#      determining the processor driving it
#--------------------------------------------------
sub isMultiTpmSystem
{
    my $targetObj = shift;
    my $targetsRef = shift;

    my $tpms=0;
    foreach my $target (@$targetsRef)
    {
        my $type = $targetObj->getType($target);
        if($type eq "TPM")
        {
            ++$tpms;
            if($tpms >1)
            {
                last;
            }
        }
    }

    return ($tpms > 1) ? 1 : 0;
} # end sub isMultiTpmSystem

#--------------------------------------------------
# @brief Get the parent pervasive value for the given unit
#
# @param[in] $targetObj - The global target object blob
# @param[in] $unit      - The chip unit to retrieve parent pervasive value for
#
# @note The $unit must be of the form <type><chip unit>, example: "core0"
#
# @return The parent pervasive value for the given unit
#--------------------------------------------------
sub getPervasiveForUnit
{
    my $targetObj = shift;
    my $unit      = shift;

    # The mapping is a static variable that is preserved across new calls to
    # the function to speed up the mapping performance
    state %unitToPervasive;
    if ( not %unitToPervasive )
    {
        %unitToPervasive = configureParentPervasiveData($targetObj, \%unitToPervasive);
    }

    my $pervasive = "";
    if(exists $unitToPervasive{$unit})
    {
        $pervasive = $unitToPervasive{$unit};
    }

    return $pervasive
}

#--------------------------------------------------
# @brief Configure the target type's parent pervasive values
#
# @param[in] $targetObj       - The global target object blob
# @param[in] %unitToPervasive - Hash function to populate with parent pervasive values
#
# @return The hash %unitToPervasive back to caller with populated
#         parent pervasive values
#--------------------------------------------------
sub configureParentPervasiveData
{
    my $targetObj       = shift;
    my %unitToPervasive = %{$_[0]};

    use integer;

    # For these targets the parent pervasive is just an incremental value
    my @commonCaseTargetTypes = qw (EQ IOHS MC MI NMMU PAUC PEC PHB);
    foreach my $targetType (@commonCaseTargetTypes)
    {
        my $maxInst = getMaxInstPerProc($targetType);
        for my $targetTypeValue (0..$maxInst-1)
        {
            $unitToPervasive{"$targetType$targetTypeValue"} =
              $targetTypeValue + getParentPervasiveOffset($targetType);
        }
    }

    # For these targets, the parent pervasive increments based on the
    # parent, in the lineage, that is a child of the targe type PROC.
    my @specialCaseTargetTypes = qw (CORE FC PAU PHB MCC OMI OMIC);
    foreach my $targetType (@specialCaseTargetTypes)
    {
        my $maxInst = getMaxInstPerProc($targetType);
        for my $targetTypeValue (0..$maxInst-1)
        {
            my $value = getParentPervasiveOffset($targetType);

            if ($targetType eq "CORE")
            {
                # The CORE pervasive parent value is not sequential.  It only
                # increases based on the parent lineage EQ which can be
                # determined by the difference of the max instance per PROC
                # for the CORE target to the EQ target.
                my $TARGET_PER_EQ = getMaxInstPerProc($targetType)/getMaxInstPerProc("EQ");
                $value += ($targetTypeValue/$TARGET_PER_EQ);
            }
            elsif ($targetType eq "FC")
            {
                # The FC pervasive parent value is not sequential.  It only
                # increases based on the parent lineage EQ which can be
                # determined by the difference of the max instance per PROC
                # for the FC target to the EQ target.
                my $TARGET_PER_EQ = getMaxInstPerProc($targetType)/getMaxInstPerProc("EQ");
                $value += ($targetTypeValue/$TARGET_PER_EQ);
            }
            elsif ($targetType eq "PAU")
            {
                # The PAU pervasive parent value is not sequential.  It only
                # increases based on the parent lineage PAUC which can be
                # determined by the difference of the max instance per PROC
                # for the PAU to the PAUC target.
                my $TARGET_PER_PAUC = getMaxInstPerProc($targetType)/getMaxInstPerProc("PAUC");
                $value += ($targetTypeValue/$TARGET_PER_PAUC);
            }
            elsif ($targetType eq "PHB")
            {
                # The PHB pervasive parent value is not sequential.  It only
                # increases based on the parent lineage PEC which can be
                # determined by the difference of the max instance per PROC
                # for the PHB to the PAUC target.
                my $PHB_PER_PEC = getMaxInstPerProc($targetType)/getMaxInstPerProc("PEC");
                $value += ($targetTypeValue/$PHB_PER_PEC);
            }
            elsif ( ($targetType eq "MCC") || ($targetType eq "OMI") || ($targetType eq "OMIC"))
            {
                # The target's pervasive parent value is not sequential.  It only
                # increases based on the parent lineage MC which can be
                # determined by the difference of the max instance per PROC
                # for said target to the MC target.
                my $TARGET_PER_MC = getMaxInstPerProc($targetType)/getMaxInstPerProc("MC");
                $value += ($targetTypeValue/$TARGET_PER_MC);
            }
            else
            {
                select()->flush(); # flush buffer before spewing out error message
                die "\n\nconfigureParentPervasiveData: ERROR: target type " .
                    "($targetType) not accounted for in loop. Error"

            }

            $unitToPervasive{"$targetType$targetTypeValue"} = $value;
        }
    } # end foreach my $targetType (@specialCaseTargetTypes)

    return %unitToPervasive;
}

sub convertNegativeNumbers
{
    my $targetObj=shift;
    my $target=shift;
    my $attribute=shift;
    my $numbits=shift;

    my @offset = split(/\,/,
                 $targetObj->getAttribute($target,$attribute));
    for (my $i=0;$i<@offset;$i++)
    {
        if ($offset[$i]<0)
        {
            my $neg_offset = 2**$numbits+$offset[$i];
            $offset[$i]=sprintf("0x%08X",$neg_offset);
        }
    }
    my $new_offset = join(',',@offset);
    $targetObj->setAttribute($target,$attribute,$new_offset)
}

sub parseBitwise
{
    my $targetObj = shift;
    my $target = shift;
    my $attribute = shift;
    my $mask = 0;

    #if CDM_POLICIES_BITMASK is not a bad attribute, aka if it is defined
    if (!$targetObj->isBadAttribute($target, $attribute."_BITMASK"))
    {
        foreach my $e (keys %{ $targetObj->getEnumHash($attribute)})
        {
            my $field = $targetObj->getAttributeField(
                        $target,$attribute."_BITMASK",$e);
            my $val=hex($targetObj->getEnumValue($attribute,$e));
            if ($field eq "true")
            {
                $mask=$mask | $val;
            }
        }
        $targetObj->setAttribute($target,$attribute,$mask);
    }
}

#--------------------------------------------------
## Compute max compute node
sub get_max_compute_nodes
{
   my $targetObj = shift;
   my $sysTarget = shift;
   my $retVal = 0;
   ##
   #Proceeed only for sys targets
   ##
   #For fabric_node_map, we store the node's position at the node
   #position's index
   my @fabric_node_map = (255, 255, 255, 255, 255, 255, 255, 255);
   if ($targetObj->getType($sysTarget) eq "SYS")
   {
      foreach my $child (@{$targetObj->getTargetChildren($sysTarget)})
      {
         if ($targetObj->isBadAttribute($child, "ENC_TYPE") == 0)
         {
            my $attrVal =  $targetObj->getAttribute($child, "ENC_TYPE");
            if ($attrVal eq "CEC")
            {
                my $fapi_pos = $targetObj->getAttribute($child, "FAPI_POS");
                $fabric_node_map[$fapi_pos] = $fapi_pos;
                $retVal++;
            }
         }
      }
      ##
      #For Open Power systems this attribute
      #is not populated, we consider default value as 1
      # for open power systems.
      ##
      if ($retVal  == 0 )
      {
         $retVal = 1;
      }

      #Convert array into a comma separated string
      my $node_map = "";
      foreach my $i (@fabric_node_map)
      {
            $node_map .= "$i,";
      }

      #remove the last comma
      $node_map =~ s/.$//;
      $targetObj->setAttribute($sysTarget, "FABRIC_TO_PHYSICAL_NODE_MAP", $node_map);
   }
   return $retVal;
}

sub setDimmTempAttributes
{
    my $targetObj = shift;
    my $target = shift;
    my $conn_target = shift;
    my $fru = shift;

    my $name = "TEMP_SENSOR_I2C_CONFIG";
    my $port = $targetObj->getAttribute($conn_target->{SOURCE}, "I2C_PORT");
    my $engine = $targetObj->getAttribute($conn_target->{SOURCE}, "I2C_ENGINE");
    my $addr = $targetObj->getAttribute($conn_target->{DEST},"I2C_ADDRESS");
    my $path = $targetObj->getAttribute($conn_target->{SOURCE_PARENT},
               "PHYS_PATH");

    $targetObj->setAttributeField($target, $name, "i2cMasterPath", $path);
    $targetObj->setAttributeField($target, $name, "port", $port);
    $targetObj->setAttributeField($target, $name, "devAddr", $addr);
    $targetObj->setAttributeField($target, $name, "engine", $engine);
}

#--------------------------------------------------
# @brief Error checking
#--------------------------------------------------
sub errorCheck
{
    my $targetObj = shift;
    my $target    = shift;
    my $type      = $targetObj->getType($target);

    ## error checking even for connections are done with attribute checks
    ##  since connections simply create attributes at source and/or destination
    ##
    ## also error checking after processing is complete vs during
    ## processing is easier
    my %attribute_checks = (
        SYS         => ['SYSTEM_NAME'],#'OPAL_MODEL'],
        PROC        => ['FSI_MASTER_CHIP', 'EEPROM_VPD_PRIMARY_INFO/devAddr'],
    );
    my %error_msg = (
        'EEPROM_VPD_PRIMARY_INFO/devAddr' =>
          'I2C connection to target is not defined',
        'FSI_MASTER_PORT' => 'This target is missing a required FSI connection',
        'FSI_MASTER_CHIP' => 'This target is missing a required FSI connection',
    );

    my @errors;
    foreach my $attr (@{ $attribute_checks{$type} })
    {
        my ($a,         $v)     = split(/\|/, $attr);
        my ($a_complex, $field) = split(/\//, $a);
        if ($field ne "")
        {
            if ($targetObj->isBadComplexAttribute(
                    $target, $a_complex, $field, $v) )
            {
                push(@errors,sprintf(
                        "$a attribute is invalid (Target=%s)\n\t%s\n",
                        $target, $error_msg{$a}));
            }
        }
        else
        {
            if ($targetObj->isBadAttribute($target, $a, $v))
            {
                push(@errors,sprintf(
                        "$a attribute is invalid (Target=%s)\n\t%s\n",
                        $target, $error_msg{$a}));
            }
        }
    }

    if ($errors[0])
    {
        foreach my $err (@errors)
        {
            print "ERROR: $err\n";
        }
        $targetObj->myExit(3);
    }
} # end sub errorCheck


#################################################################################
# utility function used to call plugins. if none exists, call is skipped.
#################################################################################
sub do_plugin
{
    my $step      = shift;
    my $targetObj = $_[0]; # Get the second argument without removing it

    if (exists($hwsvmrw_plugins{$step}))
    {
        $hwsvmrw_plugins{$step}(@_);
    }
    elsif ($targetObj->{debug} && ($targetObj->{build} eq "fsp"))
    {
        print STDERR "build is $targetObj->{build} but no plugin for $step\n";
    }
}

################################################################################
# Subroutines that support the global hashes $PARENT_PERVASIVE_OFFSET,
# MAX_INST_PER_PARENT and MAX_INST_PER_PROC
################################################################################
#--------------------------------------------------
# @brief Get the parent pervasive offset for the given target type
#
# @details This is a wrapper around the hash PARENT_PERVASIVE_OFFSET that will
#          validate the key.  If the key does not exist in the hash, then an
#          error is displayed and the script halted.  The advantage to using
#          this method over reading the hash directly, is that, Perl will
#          not flag if the key does not exist, and the programmer can easily
#          dismiss the no warning/error as everything is working fine.
#
# @note Will confess if key into hash is not found.  Confess gives a stack trace
#       which gives better info to find the offending statement as opposed to
#       'die', 'croak' or simply exiting.
#
# @param [in] $targetType - The key to look for in hash PARENT_PERVASIVE_OFFSET
#
# @return Value associated with key in hash PARENT_PERVASIVE_OFFSET if key exists,
#         else exit stating key not found in hash.
#--------------------------------------------------
sub getParentPervasiveOffset
{
    my $targetType = shift;

    if (not exists $PARENT_PERVASIVE_OFFSET{$targetType})
    {
       croak "getParentPervasiveOffset: ERROR: Key for target " .
           "type \"$targetType\" not found in hash " .
           "PARENT_PERVASIVE_OFFSET. Error";
    }

    return $PARENT_PERVASIVE_OFFSET{$targetType};
}

#--------------------------------------------------
# @brief Check if a parent pervasive offset exists in the global hash
#        PARENT_PERVASIVE_OFFSET.  Returns true, if found, false otherwise.
#
#
# @param [in] $targetType - The key to look for in hash PARENT_PERVASIVE_OFFSET
#
# @return true if key exists in hash, else false
#--------------------------------------------------
sub existsParentPervasiveOffset
{
    my $targetType = shift;

    my $retValue = true;
    if (not exists $PARENT_PERVASIVE_OFFSET{$targetType})
    {
        $retValue = false;
    }

    return $retValue;
}

#--------------------------------------------------
# @brief Get the maximum instance per parent from global hash MAX_INST_PER_PARENT.
#
# @details This is a wrapper around the hash MAX_INST_PER_PARENT that will
#          validate the key.  If the key does not exist in the hash, then an
#          error is displayed and the script halted.  The advantage to using
#          this method over reading the hash directly, is that, Perl will
#          not flag if the key does not exist, and the programmer can easily
#          dismiss the no warning/error as everything is working fine.
#
# @note Will confess if key into hash is not found.  Confess gives a stack trace
#       which gives better info to find the offending statement as opposed to
#       'die', 'croak' or simply exiting.
#
# @param [in] $targetType - The key to look for in hash MAX_INST_PER_PARENT
#
# @return Value associated with key in hash MAX_INST_PER_PARENT if key exists,
#         else exit stating key not found in hash.
#--------------------------------------------------
sub getMaxInstPerParent
{
    my $targetType = shift;

    if (not exists $MAX_INST_PER_PARENT{$targetType})
    {
        select()->flush(); # flush buffer before spewing out error message
        confess "\ngetMaxInstPerParent: ERROR: Key for target " .
           "type \"$targetType\" not found in hash " .
           "MAX_INST_PER_PARENT.\n";
    }

    return $MAX_INST_PER_PARENT{$targetType};
}

#--------------------------------------------------
# @brief Check if a maximum instance per parent exists in the global hash
#        MAX_INST_PER_PARENT.  Returns true, if found, false otherwise.
#
#
# @param [in] $targetType - The key to look for in hash MAX_INST_PER_PARENT
#
# @return true if key exists in hash, else false
#--------------------------------------------------
sub existsMaxInstPerParent
{
    my $targetType = shift;

    my $retValue = true;
    if (not exists $MAX_INST_PER_PARENT{$targetType})
    {
        $retValue = false;
    }

    return $retValue;
}

#--------------------------------------------------
# @brief Get the maximum instance per processor from global hash MAX_INST_PER_PROC.
#
# @details This is a wrapper around the hash MAX_INST_PER_PROC that will
#          validate the key.  If the key does not exist in the hash, then an
#          error is displayed and the script halted.  The advantage to using
#          this method over reading the hash directly, is that, Perl will
#          not flag if the key does not exist, and the programmer can easily
#          dismiss the no warning/error as everything is working fine.
#
# @note Will croak if key into hash is not found.
#
# @param [in] $targetType - The key to look for in hash MAX_INST_PER_PROC
#
# @return Value associated with key in hash MAX_INST_PER_PROC if key exists,
#         else confess stating key not found in hash.
#--------------------------------------------------
sub getMaxInstPerProc
{
    my $targetType = shift;

    if (not exists $MAX_INST_PER_PROC{$targetType})
    {
        select()->flush(); # flush buffer before spewing out error message
        confess "\ngetMaxInstPerProc: ERROR: Key for target " .
           "type \"$targetType\" not found in hash " .
           "MAX_INST_PER_PROC.\n";
    }

    return $MAX_INST_PER_PROC{$targetType};
}

#--------------------------------------------------
# @brief Check if a maximum instance per parent exists in the global hash
#        MAX_INST_PER_PROC. Returns true, if found, false otherwise.
#
#
# @param [in] $targetType - The key to look for in hash MAX_INST_PER_PROC
#
# @return true if key exists in hash, else false
#--------------------------------------------------
sub existsMaxInstPerProc
{
    my $targetType = shift;

    my $retValue = true;
    if (not exists $MAX_INST_PER_PROC{$targetType})
    {
        $retValue = false;
    }

    return $retValue;
}


################################################################################
# Useful Utilites
################################################################################
#--------------------------------------------------
# @brief A utility to return a given pass/fail flag as string "passed"/"failed"
#
# @param[in] $passFailBoolean - Flag indicating a pass/fail in terms of true/false.
#
# @return return string "passed" or "failed" based on input
#--------------------------------------------------
sub getPassFailString
{
    my $passFailBoolean = shift;
    my $failPassString = "passed";

    if ($passFailBoolean == false)
    {
        $failPassString = "failed";
    }

    return $failPassString;
}

#--------------------------------------------------
# @brief This is a wrapper around the calls that retrieve the HB targets
#        from given file.
#
# @param[in] $targetObj - The global target object
# @param[in] $filename  - The MRW XML file to be processed
# @param[in] $target    - The target to explore children of, if given, else
#                         will start with the top level target
#--------------------------------------------------
sub printHostbootTargetHierarchy
{
    my $targetObj = shift;
    my $filename  = shift;
    my $target    = shift;

    # Validate caller passed in a file to process.  No file, no work!
    if ($filename eq "")
    {
        select()->flush(); # flush buffer before spewing out error message
        die "\n\nprintHostbootTargetHierarchy: ERROR: " .
            "Must provide an XML file to process. Error";
    }

    $targetObj->__loadAndBuildMrwHierarchy__($filename);

    # No target given, so use the top level target
    # Must call after __loadAndBuildMrwHierarchy__
    if ($target eq undef)
    {

        $target = "/" . $targetObj->getTopLevel();
        print "$target \n";
    }

    # Get the name of the System that the MRW XML is for
    my $systemName = $targetObj->getSystemName();

    __printHostbootTargetHierarchy__($targetObj, $target);
} # end sub printHostbootTargetHierarchy

#--------------------------------------------------
# @brief This will only print targets, that HB is in interested in,
#        from the MRW XML file.
#
# @details Called from wrapper printHostbootTargetHierarchy.
#
# @note Private method, not for public consumption
#
# @param[in] $targetObj - The global target object
# @param[in] $target    - The target to explore children of.
#--------------------------------------------------
sub __printHostbootTargetHierarchy__
{
    my $targetObj = shift;
    my $target    = shift;

    # Target print control
    my $stopProcessingChildren1 = "power10-1";
    my $stopProcessingChildren2 = "fsi-slave-0";
    my $stopProcessingChildren3 = "motherboard_fault_sensor";
    my $stopProcessingChildren4 = "system_event_sensor";
    my $skipChild = "vpd_assoc_child";
    my $skipChildrenUntilDimm = "proc_socket-1";
    my $skipUntilDimm = 0;

    # Iterate over the children
    my $children = $targetObj->getTargetChildren($target);
    foreach my $child (@{ $children })
    {

        if (($child =~ m/$stopProcessingChildren1/)  ||
            ($child =~ m/$stopProcessingChildren2/)  ||
            ($child =~ m/$stopProcessingChildren3/)  ||
            ($child =~ m/$stopProcessingChildren4/) )
        {
            return;
        }

        if ($child =~ m/$skipChild/)
        {
            next;
        }

        if ($child =~ m/$skipChildrenUntilDimm/)
        {
            $skipUntilDimm = 1;
            next;
        }

        if ( ($skipUntilDimm == 1) &&
             (!($child =~ m/ddimm-connector/)) )
        {
            next;
        }

        print "$child \n";
        __printHostbootTargetHierarchy__($targetObj, $child);
    } # end foreach my $child (@{ $children })
} # end sub __printHostbootTargetHierarchy__


################################################################################
# Internal tests
################################################################################
#--------------------------------------------------
# @brief The main procedure to run the tests
#
# @param[in] $targetObj - The global target object
#--------------------------------------------------
sub runTests
{
    print "\nRunning tests: \n\n";
    my $targetObj = shift;

    # Load the XML and process the file, extracting targets and associating
    # attributes, with their data, to the targets
    loadXmlFile($targetObj);

    # Process the targets, setting the targets attributes.
    processTargets($targetObj);
    postProcessTargets($targetObj);

    # Each one of the test build on each other, if one fails then no point in
    # running the other
    testGetTopologyMode($targetObj)   &&
    testTopologyIdToTopologyIndex()   &&
    testGetTopologyIndex($targetObj);

    testMaxInstPerProc($targetObj);
}

#--------------------------------------------------
# @brief Test the method that gets the topology mode.
#
# @param[in] $targetObj - The global target object
#
# @return true if test passed, false other wise
#--------------------------------------------------
sub testGetTopologyMode
{
    print ">> Running testgetTopologyMode \n";
    my $targetObj = shift;

    my $testPassed = true;

    use constant TOPOLOGY_MODE_ATTRIBUTE => "PROC_FABRIC_TOPOLOGY_MODE";
    use constant TOPOLOGY_MODES => qw/ MODE0 MODE1 /;
    my @topologyModes = (TOPOLOGY_MODES);

    # Cache the current mode to restore later
    my $persistMode = $targetObj->getAttribute("/".$targetObj->{TOP_LEVEL},
                                               TOPOLOGY_MODE_ATTRIBUTE);

    # Test getting the topology mode
    foreach my $topologyMode (@topologyModes)
    {
        $targetObj->setAttribute("/".$targetObj->{TOP_LEVEL},
                                 TOPOLOGY_MODE_ATTRIBUTE,
                                 $topologyMode);
        my $topologyModeNumber = chop($topologyMode);
        if (getTopologyMode($targetObj) != $topologyModeNumber)
        {

            $testPassed = false;
            print "ERROR: Expected topology mode '$topologyModeNumber' but got " .
                   getTopologyMode($targetObj) . "\n";
        }
    }

    # Restore mode
    $targetObj->setAttribute("/".$targetObj->{TOP_LEVEL},
                             TOPOLOGY_MODE_ATTRIBUTE,
                             $persistMode);

    print "<< Running testgetTopologyMode: test " .
          getPassFailString($testPassed) . "\n";

    return $testPassed;
}

#--------------------------------------------------
# @brief Tests the conversion method that converts the topology ID,
#        with given topology mode, to the topology index.
#
# @return true if test passed, false other wise
#--------------------------------------------------
sub testTopologyIdToTopologyIndex
{
    print ">> Running testTopologyIdToTopologyIndex \n";

    my $testPassed = true;

    # The different values expected when mode is 0 or 1
    use constant TOPOLOGY_MODE_0_ARRAY => qw/ 0 1 4 5 8 9 12 13 16 17 20 21 24 25 28 29 /;
    use constant TOPOLOGY_MODE_1_ARRAY => qw/ 0 1 2 3 8 9 10 11 16 17 18 19 24 25 26 27 /;

    # The different topology modes
    use constant TOPOLOGY_MODES => qw/ MODE0 MODE1 /;
    my @topologyModes = (TOPOLOGY_MODES);

    # Default with mode 0
    my @toplogyModeArray = (TOPOLOGY_MODE_0_ARRAY);

    # Test the conversion on the different IDs and modes
    for my $topologyMode (@topologyModes)
    {
        my $topologyModeNumber = chop($topologyMode);
        if (1 == $topologyModeNumber)
        {
            @toplogyModeArray = (TOPOLOGY_MODE_1_ARRAY);
        }

        # Needed variable
        my $topologyIndex = 0;

        # Iterate thru each permutation of the topology ID and
        # test conversion to index
        for (my $topologyId = 0; $topologyId < 16; ++$topologyId)
        {
            $topologyIndex = convertTopologyIdToIndex($topologyId,
                                                      $topologyModeNumber);
            if ($topologyIndex != $toplogyModeArray[$topologyId])
            {
                $testPassed = false;
                print "ERROR: conversion on topology Id($topologyId) with ";
                print "topology mode($topologyMode) returned ";
                print "topology index($topologyIndex), but expected ";
                print "topology index($toplogyModeArray[$topologyId]) \n";
            }
        } # end for (my $topologyId = 0 ...
    } # end foreach my $topologyMode (@topologyModes)

    print "<< Running testTopologyIdToTopologyIndex: test " .
          getPassFailString($testPassed) . "\n";

    return $testPassed;
}

#--------------------------------------------------
# @brief Test the method that gets the topology index based
#        based on the current processors within the MRW XML
#
# @param[in] $targetObj - The global target object
#
# @return true if test passed, false other wise
#--------------------------------------------------
sub testGetTopologyIndex
{
    my $targetObj = shift;

    my $testPassed = true;

    my $system_name = $targetObj->getAttribute('/sys-0',"SYSTEM_NAME");
    if ($system_name =~ /RAINIER/i)
    {
        print ">> Running testGetTopologyIndex \n";

        # The different procs available
        use constant PROC_0 => "/sys-0/node-0/nisqually-0/proc_socket-0/godel-0/power10-0";
        use constant PROC_1 => "/sys-0/node-0/nisqually-0/proc_socket-0/godel-0/power10-1";

        # Get processor 1's index
        my $processorTarget = PROC_0;
        my $topologyIndex = getTopologyIndex($targetObj, $processorTarget);

        # For the current MRW, proc 0 has index 0 with mode 0
        my $expectedTopologyIndex = 0;
        if ($topologyIndex != $expectedTopologyIndex)
        {
            $testPassed = false;
            my @fullProc = split(/\//, $processorTarget);
            print "ERROR: retrieved topology index $topologyIndex for processor " .
                   "@fullProc[-1] but expected $expectedTopologyIndex \n";
        }

        # Get processor 2's index
        $processorTarget = PROC_1;
        $topologyIndex = getTopologyIndex($targetObj, $processorTarget);

        # For the current MRW, proc 1 has index 4 with mode 0
        $expectedTopologyIndex = 4;
        if ($topologyIndex != $expectedTopologyIndex)
        {
            $testPassed = false;
            my @fullProc = split(/\//, $processorTarget);
            print "ERROR: retrieved topology index $topologyIndex for processor " .
                   "@fullProc[-1] but expected $expectedTopologyIndex \n";
        }

        print "<< Running testGetTopologyIndex: test " .
              getPassFailString($testPassed) . "\n";

    } # end if ($system_name =~ /RAINIER/i)

    return $testPassed;
}

#--------------------------------------------------
# @brief Test that maixumum instance per PROC have the right values.
#
# @param[in] $targetObj - The global target object
#
# @return true if test passed, false other wise
#--------------------------------------------------
sub testMaxInstPerProc
{
    print ">> Running testMaxInstPerProc \n";

    my $targetObj = shift;

    my $testPassed = true;

    my %targetPerProc =
    (
        EQ        => 8,
        FC        => 16,
        CORE      => 32,

        MC        => 4,
        MI        => 4,
        MCC       => 8,
        OMI       => 16,
        OCMB_CHIP => 16,
        MEM_PORT  => 16,
        DDIMM     => 16,
        PMIC      => 32,
        OMIC      => 8,

        PAUC      => 4,
        IOHS      => 8,
        PAU       => 8,

        NMMU      => 2,
        OCC       => 1,
        NX        => 1,
        PEC       => 2,

        SEEPROM   => 1,
        OSCREFCLK => 1,
        PHB       => 6,
        PERV      => 56,

    );

    foreach my $target (keys %targetPerProc)
    {
        if (getMaxInstPerProc("$target") != $targetPerProc{$target})
        {
            print "ERROR: getMaxInstPerProc(\"$target\") returned " .
                   getMaxInstPerProc("$target") .
                   ", but expected " . $targetPerProc{$target} . "\n";
            $testPassed = $targetPerProc{$target};
        }

    }

    print "<< Running testMaxInstPerProc: test " .
          getPassFailString($testPassed) . "\n";

    return $testPassed;
}


################################################################################
# Orphaned methods where the calling code have been deleted.
# @TODO Remove these orphaned methods once done with current MRW XML
#       and determine that these are not no longer needed.
################################################################################
#--------------------------------------------------
# @brief Set the Target's attribute CHIPLET_ID
#
# @details The CHIPLET_ID value is calculated via the addition of the
#          target's attribute CHIP_UNIT with the PARENT_PERVASIVE_OFFSET value
#          for target type.
#
# @param [in] $targetObj - The global target object.
# @param [in] $target - target to set CHIPLET_ID for
# @param [in] $targetType - The target type of the target
# @param [in] $chipUnit - The CHIP_UNIT value used to calculate the CHIPLET_ID
#
# @note The $chipUnit may be supplied for the child to use in calculating
#       the CHIPLET_ID, if not supplied, then will use child's CHIP_UNIT value.
#
# @return true if attribute found, else false
#--------------------------------------------------
sub setTargetChipletId
{
    my $targetObj = shift;
    my $target    = shift;
    my $targetType = shift;
    my $chipUnit = shift;

    # If no chip unit given, then use the target's chip unit
    if ($chipUnit eq undef)
    {
        if ($targetObj->doesAttributeExistForTarget($target, "CHIP_UNIT"))
        {
            $chipUnit = $targetObj->getAttribute($target, "CHIP_UNIT");
        }
        else
        {
            # Can't get the CHIP_UNIT value, then no point in continuing
            # This is an acceptable response, not all target instance have
            # a CHIP_UNIT attribute.
            return;
        }
    }

    # If the target has pervasive parent, then process it
    if (exists $PARENT_PERVASIVE_OFFSET{$targetType})
    {
        # Get this target's PERVASIVE_PARENT value
        my $value = $PARENT_PERVASIVE_OFFSET{$targetType};

        if ($targetType eq "PAU")
        {
            # We divide by 2 here because the PERVASIVE_PARENT repeats in pairs
            $value += ($chipUnit / 2);
        }
        else
        {
            # Add the CHIP_UNIT value to the pervasive parent offset
            $value += $chipUnit;
        }

        # Make it look pwetty
        $value = sprintf("0x%0.2X", $value);

        # Set the chiplet ID with calculated value
        $targetObj->setAttribute( $target, "CHIPLET_ID", $value);
    }

    # Set the Chiplet ID for the children, if children exists
    if ($targetObj->getTargetChildren($target) ne "")
    {
        # Iterate over the children setting their Chiplet IDs
        foreach my $child (@{ $targetObj->getTargetChildren($target) })
        {
            # Get the target type of the child for logging
            my $childType = $targetObj->getType($child);

            $targetObj->log($target,
                "Processing $targetType child: $child Type: $childType");

            if ($childType eq "IOHS")
            {
                # Don't send THIS chip unit, let IOHS use it's own chip unit
                setTargetChipletId($targetObj, $child, $childType);
            }
            elsif ($childType eq "PAU")
            {
                setPauOrdinalId($targetObj, $child);
                setTargetChipletId($targetObj, $child, $childType, $chipUnit);
            }
            else
            {
                setTargetChipletId($targetObj, $child, $childType, $chipUnit);
            }
        }
    }
} # end sub setTargetChipletId

sub getI2cMapField
{
    my $targetObj = shift;
    my $target = shift;
    my $conn_target = shift;


    my $port = $targetObj->getAttribute($conn_target->{SOURCE}, "I2C_PORT");
    my $engine = $targetObj->getAttribute($conn_target->{SOURCE}, "I2C_ENGINE");
    my $addr = "";

    # For Open Power systems continue to get the I2C_ADDRESS from
    # bus target, if defined.
    if ($targetObj->isBusAttributeDefined(
           $conn_target->{SOURCE},$conn_target->{BUS_NUM},"I2C_ADDRESS"))
    {
        $addr = $targetObj->getBusAttribute($conn_target->{SOURCE},
            $conn_target->{BUS_NUM}, "I2C_ADDRESS");
    }
    # If bus doesn't have I2C_ADDRESS or default value is not set,
    # then get it from i2c-slave, if defined.
    if ($addr eq "")
    {
        if (! $targetObj->isBadAttribute($conn_target->{DEST},"I2C_ADDRESS") )
        {
           $addr = $targetObj->getAttribute($conn_target->{DEST},"I2C_ADDRESS");
        }
    }

    #if the addr is still not defined, then throw an error
    if ($addr eq "")
    {
        print ("ERROR: I2C_ADDRESS is not defined for $conn_target\n");
        $targetObj->myExit(4);
    }

    my $bits=sprintf("%08b",hex($addr));
    my $field=sprintf("%d%3s",oct($port),substr($bits,4,3));
    my $hexfield = sprintf("%X",oct("0b$field"));
    return $hexfield;
}

# convert a number string into a bit-position number
# example:  "0x02" -->  0b0100 = 4
sub numToBitPositionNum
{
    my ($hexStr) = @_;

    my $num = 0x0001;
    my $newNum = $num << hex($hexStr);

    return $newNum;
} # end sub numToBitPositionNum

sub setGpioAttributes
{
    my $targetObj = shift;
    my $target = shift;
    my $conn_target = shift;
    my $vddrPin = shift;

    my $port = $targetObj->getAttribute($conn_target->{SOURCE}, "I2C_PORT");
    my $engine = $targetObj->getAttribute($conn_target->{SOURCE}, "I2C_ENGINE");
    my $addr = $targetObj->getBusAttribute($conn_target->{SOURCE},
            $conn_target->{BUS_NUM}, "I2C_ADDRESS");
    my $path = $targetObj->getAttribute($conn_target->{SOURCE_PARENT},
               "PHYS_PATH");


    my $name="GPIO_INFO";
    $targetObj->setAttributeField($target, $name, "i2cMasterPath", $path);
    $targetObj->setAttributeField($target, $name, "port", $port);
    $targetObj->setAttributeField($target, $name, "devAddr", $addr);
    $targetObj->setAttributeField($target, $name, "engine", $engine);
    $targetObj->setAttributeField($target, $name, "vddrPin", $vddrPin);
}

#--------------------------------------------------
## ABUS
##
## Finds ABUS connections and creates PEER TARGET attributes
sub processAbus
{
    my $targetObj = shift;
    my $target    = shift;
    my $aBus      = shift;

    my $abussource = $aBus->{SOURCE};
    my $abusdest   = $aBus->{DEST};
    my $abus_dest_parent = $aBus->{DEST_PARENT};
    my $bustype = $targetObj->getBusType($abussource);
    my $updatePeerTargets = 0;


    my $config = $targetObj->getBusAttribute($aBus->{SOURCE},$aBus->{BUS_NUM},"CONFIG_APPLY");
    my $twonode = "2";
    my $threenode = "3";
    my $fournode = "4";
    my @configs = split(',',$config);

    # The CONFIG_APPLY bus attribute carries a comma seperated values for each
    # A-bus connection. For eg.,
    # "2,3,4" - This connection is applicable in 2,3 and 4 node config
    # "w" - This connection is applicable only in wrap config
    # "2" - This connection is applicable only in 2 node config
    # "4" - This connection is applicable only in 4 node config
    # The below logic looks for these tokens and decides whether a certain
    # A-bus connection has to be conisdered or not
    # If user has passed 2N as argument, then we consider only those
    # A-bus connections where token "2" is present
    my $system_config = $targetObj->{system_config};
    if($system_config eq "2N" && $config =~ /$twonode/)
    {
        #Looking for Abus connections pertaining to 2 node system only
        $updatePeerTargets = 1;
    }
    elsif ($system_config eq "")
    {
      #Looking for Abus connections pertaining to 2,3,4 node systems
      #This will skip any connections specific to ONLY 2 node
      if($config =~ /$threenode/ || $config =~ /$fournode/)
      {
          $updatePeerTargets = 1;
      }

    }
    elsif ($config =~ /$system_config/)
    {
        #If system configuration we are building for matches the config
        #this ABUS connection is for, then update. Ex: wrap config
        $updatePeerTargets = 1;
    }
    else
    {
        $updatePeerTargets = 0;
    }


    if($updatePeerTargets eq 1)
    {
        ## set attributes for both directions
        my $phys1 = $targetObj->getAttribute($target, "PHYS_PATH");
        my $phys2 = $targetObj->getAttribute($abus_dest_parent, "PHYS_PATH");

        $targetObj->setAttribute($abus_dest_parent, "PEER_TARGET",$phys1);
        $targetObj->setAttribute($target, "PEER_TARGET",$phys2);
        $targetObj->setAttribute($abus_dest_parent, "PEER_PATH", $phys1);
        $targetObj->setAttribute($target, "PEER_PATH", $phys2);

        $targetObj->setAttribute($abus_dest_parent, "PEER_HUID",
           $targetObj->getAttribute($target, "HUID"));
        $targetObj->setAttribute($target, "PEER_HUID",
           $targetObj->getAttribute($abus_dest_parent, "HUID"));

        $targetObj->setAttribute($abussource, "PEER_TARGET",
                 $targetObj->getAttribute($abusdest, "PHYS_PATH"));
        $targetObj->setAttribute($abusdest, "PEER_TARGET",
                 $targetObj->getAttribute($abussource, "PHYS_PATH"));

        $targetObj->setAttribute($abussource, "PEER_PATH",
                 $targetObj->getAttribute($abusdest, "PHYS_PATH"));
        $targetObj->setAttribute($abusdest, "PEER_PATH",
                 $targetObj->getAttribute($abussource, "PHYS_PATH"));

        $targetObj->setAttribute($abussource, "PEER_HUID",
           $targetObj->getAttribute($abusdest, "HUID"));
        $targetObj->setAttribute($abusdest, "PEER_HUID",
           $targetObj->getAttribute($abussource, "HUID"));

        # copy attributes for wrap config
        my $link_set = "SET_NONE";
        if ($targetObj->isBusAttributeDefined($aBus->{SOURCE},$aBus->{BUS_NUM},"MFG_WRAP_TEST_ABUS_LINKS_SET"))
        {
            $link_set = $targetObj->getBusAttribute($aBus->{SOURCE},$aBus->{BUS_NUM},"MFG_WRAP_TEST_ABUS_LINKS_SET");
        }
        $targetObj->setAttribute($target, "MFG_WRAP_TEST_ABUS_LINKS_SET", $link_set);
        $targetObj->setAttribute($abus_dest_parent, "MFG_WRAP_TEST_ABUS_LINKS_SET", $link_set);
    }
} # end sub processAbus

#--------------------------------------------------
## OBUS
##
## Finds OBUS connections and copy the slot position to obus brick target
sub processObus
{
    my $targetObj = shift;
    my $target    = shift;

    my $obus = $targetObj->findConnections($target,"OBUS", "");

    if ($obus eq "")
    {
        $obus = $targetObj->findConnections($target,"ABUS", "");
        if ($obus ne "")
        {
           $targetObj->setAttribute($target, "BUS_TYPE", "ABUS");
           if ($targetObj->isBadAttribute($target, "PEER_PATH"))
           {
              $targetObj->setAttribute($target, "PEER_PATH","physical:na");
           }
           foreach my $obusconn (@{$obus->{CONN}})
           {
              processAbus($targetObj, $target,$obusconn);
           }
        }
        else
        {
          #No connections mean, we need to set the OBUS_SLOT_INDEX to -1
          #to mark that they are not connected
          $targetObj->log($target,"no bus connection found");

          foreach my $obrick (@{ $targetObj->getTargetChildren($target) })
          {
             $targetObj->setAttribute($obrick, "OBUS_SLOT_INDEX", -1);
          }
        }
     }
     else
     {
        if ($targetObj->isBadAttribute($target, "PEER_PATH"))
        {
           $targetObj->setAttribute($target, "PEER_PATH","physical:na");
        }
        foreach my $obusconn (@{$obus->{CONN}})
        {
             #Loop through all the bricks and figure out if it connected to an
             #obusslot. If it is connected, then store the slot information (position)
             #in the obus_brick target as OBUS_SLOT_INDEX. If it is not connected,
             #set the value to -1 to mark that they are not connected
             my $match = 0;
             foreach my $obrick (@{ $targetObj->getTargetChildren($target) })
             {
               foreach my $obrick_conn (@{$obus->{CONN}})
               {
                 if ($targetObj->isBusAttributeDefined($obrick,
                                     $obrick_conn->{BUS_NUM}, "OBUS_CONFIG"))
                 {
                     my $cfg = $targetObj->getBusAttribute($obrick,
                                     $obrick_conn->{BUS_NUM}, "OBUS_CONFIG");
                     my $intarget = $obrick_conn->{SOURCE_PARENT};
                     while($targetObj->getAttribute($intarget,"CLASS") ne "CONNECTOR")
                     {
                       $intarget = $targetObj->getTargetParent($intarget);
                     }
                 }

                 $match = ($obrick_conn->{SOURCE} eq $obrick);
                 if ($match eq 1)
                 {
                     my $obus_slot    = $targetObj->getTargetParent(
                         $obrick_conn->{DEST_PARENT});
                     my $obus_slot_pos = $targetObj->getAttribute(
                            $obus_slot, "POSITION");
                        $targetObj->setAttribute($obrick, "OBUS_SLOT_INDEX",
                            $obus_slot_pos);
                        last;
                 }
               }

               #This brick is not connected to anything, set the value of OBUS_SLOT_INDEX to -1
               #to mark that they are not connected
               if ($match eq 0)
               {
                  $targetObj->setAttribute($obrick, "OBUS_SLOT_INDEX", -1);
               }
            }
     }
   }

    my $chip_unit = $targetObj->getAttribute($target, "CHIP_UNIT");
    my $value = sprintf("0x%x", getParentPervasiveOffset("OBUS_BRICK") + $chip_unit);
    $targetObj->setAttribute($target, "CHIPLET_ID", $value);

    # Set CHIPLET_ID for OBUS_BRICKs
    foreach my $child (@{ $targetObj->getTargetChildren($target) })
    {
        my $type = $targetObj->getType($child);
        if ($type eq "OBUS_BRICK")
        {
            # OBUS_BRICK takes on CHIPLET_ID of OBUS parent
            $targetObj->setAttribute($child, "CHIPLET_ID", $value);
        }
    }
} # end sub processObus

#--------------------------------------------------
## XBUS
##
## Finds XBUS connections and creates PEER TARGET attributes
sub processXbus
{
    my $targetObj = shift;
    my $target    = shift;

    my $found_xbus = 0;
    my $default_config = "d";
    my $wrap_config    = "w";
    my $xbus_child_conn = $targetObj->getFirstConnectionDestination($target);
    if ($xbus_child_conn ne "")
    {
        # The CONFIG_APPLY bus attribute carries a comma seperated values for each
        # X-bus connection. It can currently take the following values.
        # "w" - This connection is applicable only in wrap config
        # "d" - This connection is applicable in default config (non-wrap mode).
        my $config = $default_config;
        if ($targetObj->isBusAttributeDefined($target,0,"CONFIG_APPLY"))
        {
            $config = $targetObj->getBusAttribute($target,0,"CONFIG_APPLY");
        }

        # Validate a value was provided, if not use the default value
        if ($config eq "")
        {
            print STDOUT "No value found for CONFIG_APPLY, default to using default value ($default_config)\n";
            $config = $default_config;
        }

        #If CONFIG_APPLY doesn't match the system configuration we are
        #running for, then mark the peers null.
        #For example, in wrap config, CONFIG_APPLY is expected to have "w"
        #If "w" is not there, then we skip the connection and mark peers
        #as NULL
        my $system_config = $targetObj->{system_config};
        if (($system_config eq $wrap_config && $config =~ /$wrap_config/) ||
           ($system_config ne $wrap_config && $config =~ /$default_config/))
        {
            ## set attributes for both directions
            $targetObj->setAttribute($xbus_child_conn, "PEER_TARGET",
                $targetObj->getAttribute($target, "PHYS_PATH"));
            $targetObj->setAttribute($target, "PEER_TARGET",
                $targetObj->getAttribute($xbus_child_conn, "PHYS_PATH"));

            $targetObj->setAttribute($xbus_child_conn, "PEER_PATH",
                $targetObj->getAttribute($target, "PHYS_PATH"));
            $targetObj->setAttribute($target, "PEER_PATH",
                $targetObj->getAttribute($xbus_child_conn, "PHYS_PATH"));

            $targetObj->setAttribute($xbus_child_conn, "PEER_HUID",
                $targetObj->getAttribute($target, "HUID"));
            $targetObj->setAttribute($target, "PEER_HUID",
                $targetObj->getAttribute($xbus_child_conn, "HUID"));

            $found_xbus = 1;
        }
        else
        {
            $targetObj->setAttribute($xbus_child_conn, "PEER_TARGET", "NULL");
            $targetObj->setAttribute($target, "PEER_TARGET","NULL");
            $targetObj->setAttribute($xbus_child_conn, "PEER_PATH", "physical:na");
            $targetObj->setAttribute($target, "PEER_PATH", "physical:na");
        }
    }
} # end sub processXbus
