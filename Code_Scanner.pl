#!/usr/bin/perl
###################################################################################################
# File      : Code_Scanner.pl
# Objective : To ensure no malicious code is injected inside the contents
#                1. using "svn diff" for existing files and checking its contents
#	         2. using "svn stat" for new files and checking its contents  
#                adequate comments have been given before not-so-regualar lines to ease reading.  
# author    : Siva Guruvareddiar
# version   : 1.0
###################################################################################################

   use strict;
   use XML::Simple;
  
   my %config= &loadConfigFile('./config.txt');
   my $targetFilename=$config{'diffFilename'};
   my $svnBaseDir = $config{'svnBaseDir'};
   my $classpath=$config{'classpath'};
   my $malicious_file_list =$config{'malicious_file_list_name'};
   my $xmlPatternFile=$config{'XMLPatternfilename'};
   our @patternArr= &loadPatternsFromXMLConfigFile($xmlPatternFile);
   open(mFP,">$malicious_file_list");
   
   &doSVNDiffViaCommandLine($targetFilename);
   
   #Get the line numbers containing "Index:" that contains the name of the file and delimit with :
   my $filename_LineNos = `cat $targetFilename |  grep -n \"^Index: \" | cut -d':' -f1 | tr \\\\\\n :`;
   
   #get the total no. of lines of "svn diff" output
    my $fileLen=`wc -l $targetFilename | /usr/bin/awk '{print \$1}'`;
   
   #Strip off the whitespaces both leading and trailing
   $fileLen=~ s/^\s+//;
   $fileLen=~ s/\s+$//;
   
   #append the total line no. count to the previous string which contains "Index:" line no.s
   $filename_LineNos.=$fileLen;
   
   #Going to process each and every file diff 
   my @filename_LineNosList = split(/:/,$filename_LineNos);
   
   for (my $i=0;$i<$#filename_LineNosList;$i++)
   { 
     my $diffStartingLine=$filename_LineNosList[$i];
     my $diffEndingLine=$filename_LineNosList[$i+1];
     #Flag to ensure only the malicious file name is inserted only once 
      my $isMalicious=0;    
     #check atleast 6 lines exists in between so as to ensure processing single file
      if ($diffEndingLine-$diffStartingLine >=6) 
          {
            #get the name of the file 
            my $filename =`cat $targetFilename | sed -n '$diffStartingLine,$diffEndingLine p'| grep \"^Index: \" | head -1 |cut -d':' -f2`;
            #get the list of lines which are deleted(-) or added(+)
            my @deletedPatterns= findPatternsInsideDiffContents($diffStartingLine,$diffEndingLine,"-");
            my @addedPatterns= findPatternsInsideDiffContents($diffStartingLine,$diffEndingLine,"+");
           
            #foreach added Pattern, check whether its not added, by cross verifying with deletedPatterns list 
            foreach my $element (@addedPatterns){ 
               if (!grep {$_ eq $element} @deletedPatterns) {
                   if($isMalicious==0){
     			$filename=~ s/^\s+//;
			$filename=~ s/\s+$//;
                        print mFP "$filename\n";
                        $isMalicious=1;
                   } 
               }
           }
           $isMalicious=0; #revert back the status for next files
       }
   }

   #  ************* Code scanning for newly added files START 
   #Find the status to check any new files added (First time to be checked into SVN)
   my $listofNewFiles;
   $listofNewFiles=&doSVNStatusViaCommandLine();
    
   #if any files added newly, then start the process
   if ($listofNewFiles ne ""){
       my @newFilesAr=split(/:/,$listofNewFiles);
       foreach my $newFile (@newFilesAr){
          # Regex for finding zh_TW $1+$2+$3=Absolute path of $newFile
              ### "$1=>Parent Directory" "$2=>zh_TW string" "$3=>string after zh_TW String"
          if($newFile=~ /([a-zA-z0-9\/\-_\.]*)(\/[a-zA-Z0-9\-\._]*zh_TW\/)([a-zA-z0-9\/\-_\.]*)/ ){
             #Go inside the parent directory: and check the file present  
             my $cmd=chdir $1;
             if (-e $3){ 
                #English version of the file found. Start checking for any malicious code  
                findDiffOfNewFile($newFile, $1."\/".$3);
             }
             else{
                #the file is not present here, start searching in list of dir.s from config file
                my @availableDirsArr=split(/\,/,$config{'available_Directories'});
                #ensure the filename doesn't contain any dir path
                my $fileNameOnlyString=substr($3, rindex($3,"\/")+1);
                my $foundFlag=0;
                my $dirIndex=0;
                for (;($dirIndex<=$#availableDirsArr && $foundFlag==0);$dirIndex++){
                   $cmd=`cd $availableDirsArr[$dirIndex];find . -name $fileNameOnlyString`;
                   if ($cmd ne ""){$foundFlag=1;}
                }   
                if($foundFlag ==1){
                  findDiffOfNewFile($newFile,$availableDirsArr[$dirIndex-1]."\/".substr($cmd,2)); 
                }
                  $foundFlag=0;
             } 
          }
         
      } 
   }
   
   # **************  Code scanning for newly added files END  

   # Reporting - checks the malicious content aggregation file. If empty no malicious content.
   my $malicious_file_count=`wc -l $malicious_file_list | /usr/bin/awk '{print \$1}'`;
   if ($malicious_file_count==0){
       print "##############################################################################\n";
       print " Code Scanning -- DONE \n";
       print " Hooray !!! No files contain malicious content\n";
       print "##############################################################################\n";    
   }
   else{
      `/usr/bin/uniq $malicious_file_list`;
       print "##############################################################################\n";
       print " Code Scanning -- DONE \n";
       print " Please open $malicious_file_list to see list of Malicious files\n";
       print "##############################################################################\n";    
   }

   close(mFP);

########################################################################################################
# Method  : findPatternsInsideDiffContents
# Purpose : given the starting and ending line no.s, this method finds the added(+)/deleted(-) lines
#           applies Regex patterns and stores them in an array
# Input   : Starting Line no., Ending Line no., added(+)/deleted(-) symbol
# Output  : Returns array containing patterns
########################################################################################################

sub findPatternsInsideDiffContents(){
   my @addedPatternArr;
   my $diffStartingLine = shift;
   my $diffEndingLine = shift;
   my $symbol = shift;
   my $diffLinesScalar = `cat $targetFilename | sed -n '$diffStartingLine,$diffEndingLine p'  |   grep \"^$symbol\" | grep -v \"(working copy)\" | grep -v \"(revision \"`;

   #Go thro each line to check whether the line matches the regex from XML config file  
   $symbol= "\\".$symbol;
   my @diffLinesArr=split(/$symbol/,$diffLinesScalar);
   foreach my $line (@diffLinesArr){
    $line=~ s/^\s+//;
    $line=~ s/\s$//;
    if (length($line)!=0) {
       foreach my $regex (@patternArr){   
           if ($line =~ /($regex)/){
                    push(@addedPatternArr,$1);
            }   
        }
      } 
   }
   return @addedPatternArr;
}



########################################################################################################
# Method  : doSVNDiffViaCommandLine
# Purpose : Invoke "svn diff" using the command line client and redirect the output to a file
# Input   : filename to be redirected
# Output  : None
#########################################################################################################

sub doSVNDiffViaCommandLine(){ 
   my $targetFilename =shift;
   `svn diff $svnBaseDir > $targetFilename`;
}



########################################################################################################
# Method  : loadPatternsFromXMLConfigFile
# Purpose : Loads the patterns from the XML config file by parsing it 
# Input   : XML config file
# Output  : Array containing the patterns
#########################################################################################################

sub loadPatternsFromXMLConfigFile(){
   my $xmlConfigFile=shift;
   my $mldata= XMLin($xmlConfigFile);
   my $rules=$mldata->{rule};
   my @PatternArr;
   foreach my $id (keys %$rules)
     {
        push (@PatternArr,$rules->{$id}->{pattern});
     }
   return @PatternArr;
}



########################################################################################################
# Method  : loadConfigFile
# Purpose : Loads the Configuration file and returns the contents as a hash 
# Input   : config file name
# Output  : Hash
#########################################################################################################

sub loadConfigFile(){
   my $configFile=shift;
   my %config;
   open my $configFP, "$configFile" or die $!;
   while(<$configFP>) {
        chomp;
        (my $key, my @value) = split /=/, $_;
        $config{$key} = join '=', @value;
    }
   return %config;
}



########################################################################################################
# Method  : doSVNStatusViaCommandLine
# Purpose : Invoke "svn status" using the command line client 
# Input   : None
# Output  : None
#########################################################################################################

sub doSVNStatusViaCommandLine(){ 
   my $listOfNewFiles=`svn stat $svnBaseDir | grep \"^?\" | awk '{print \$2}' |tr \\\\\\n ':'`;
   return $listOfNewFiles;
}



########################################################################################################
# Method  : findDiffOfNewFile
# Purpose : Finds the differece between English and foreign language (now Chinese) files and 
#           detects if there any malicious content added by applying xml rules
# Input   : Filename contains non-English contents (Chinese) and Filename contains English contents
# Output  :
########################################################################################################

sub findDiffOfNewFile(){
    my $non_EnglishFile=shift;
    my $englishFile=shift;
    my $isMalicious=0;
    chomp($englishFile);
    chomp($non_EnglishFile);
    my $cmd=`/usr/bin/diff $englishFile $non_EnglishFile > $targetFilename`;
    my @addedPatterns = &findPatternsInsideNewFileDiff(">");
    my @deletedPatterns=&findPatternsInsideNewFileDiff("<");

    #foreach added Pattern, check whether its not added, by cross verifying with deletedPatterns list
     foreach my $element (@addedPatterns){
        if (!grep {$_ eq $element} @deletedPatterns) {
            if($isMalicious==0){
                 $non_EnglishFile=~ s/^\s+//;
                 $non_EnglishFile=~ s/\s+$//;
                 print mFP "$non_EnglishFile\n";
                 $isMalicious=1;
             }
        }
     }
}

########################################################################################################
# Method  : findPatternsInsideNewFileDiff
# Purpose : given the diff file, this method finds the added(>)/deleted(<) lines
#           applies Regex patterns and stores them in an array
# Input   : added(>)/deleted(<) symbol
# Output  : Returns array containing patterns
########################################################################################################

sub findPatternsInsideNewFileDiff(){
   my @addedPatternArr;
   my $symbol = shift;
   my $diffLinesScalar = `cat $targetFilename | grep \"^$symbol \" `;

   #Go thro each line to check whether the line matches the regex from XML config file
   my @diffLinesArr=split(/$symbol /,$diffLinesScalar);
   foreach my $line (@diffLinesArr){
    $line=~ s/^\s+//;
    $line=~ s/\s$//;
    if (length($line)!=0) {
       foreach my $regex (@patternArr){
           if ($line =~ /($regex)/){
                    push(@addedPatternArr,$1);
            }
        }
      }
   }
   return @addedPatternArr;
}
