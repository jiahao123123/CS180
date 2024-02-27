# These are some imports that I found useful when implementing this project, you can use other libraries if you prefer.
# Note that you should only use standard python libraries. You should NOT use any existing testing framework libraries.

import time
import sys
import os

import argparse
import subprocess
import telnetlib
from telnetlib import Telnet
from glob import glob
import re

TEST_CASES_PATH = "testing_environment/testcases/"
TEMP_DIRECTORY_PATH = "./testing_environment/temp"

def verbose_print(string_to_print):
  if (args.verbose):
    print(string_to_print)

def attempt_regex(expected, output, repeat_regex, repeat_regexes_left):
    can_read_next_expected = True
    line_matched = False
    needs_to_match = True
    matched_zero_times = False

    if repeat_regex != "" or (len(expected) > 0 and expected[0:1] == '^'):
      repeat_regex_indicator = expected[-2:]
      if repeat_regex == "":
        if repeat_regex_indicator == "$+":
          repeat_regex = expected[0:-1]
          repeat_regexes_left = 1
        elif repeat_regex_indicator == "$*":
          #verbose_print("found asterisk")
          repeat_regex = expected[0:-1]
          repeat_regexes_left = 0
          needs_to_match = False

      if repeat_regex != "":
        line_matched = re.search(repeat_regex, output) != None

        if line_matched:
          repeat_regexes_left -= 1

        if not (line_matched) and not (needs_to_match) and repeat_regexes_left == 0:
          matched_zero_times = True
      else:
        line_matched = re.search(expected, output) != None

      if (needs_to_match) and repeat_regexes_left > 0:
        can_read_next_expected = False
      #verbose_print("matched regex: " + str(line_matched))

    return line_matched, repeat_regex, repeat_regexes_left, can_read_next_expected, matched_zero_times

def verify_output_vs_expected(line_str, is_creating_pasv, telnet_list, pasv_ports, client_num, expected_file, testcase_name, line_num, retr_output_buffer):
  is_test_passed = True
  repeat_regex = ""
  repeat_regexes_left = 0
  expected = "~"

  cur_client_num = 0
  while cur_client_num < len(telnet_list):
    while telnet_list[cur_client_num] != None:
      if len(retr_output_buffer) > 0:
        partition_index = retr_output_buffer.find("\r\n")

        if partition_index < 0 or partition_index >= len(retr_output_buffer):
          output = retr_output_buffer.strip("\r\n")
          retr_output_buffer = ""
          #verbose_print("1 output: " + str(output.encode()) + "    output_buffer: " + str(retr_output_buffer.encode()))
        else:
          #verbose_print("partition_index: " + str(partition_index))
          output = retr_output_buffer[0:partition_index].strip(" \r\n")
          retr_output_buffer = retr_output_buffer[partition_index:len(retr_output_buffer)].lstrip(" \r\n")
          #verbose_print("2 output: " + str(output.encode()) + "    output_buffer: " + str(retr_output_buffer.encode()))
      else:
        try:
          output = telnet_list[cur_client_num].read_until(b"\r\n", 1)
          output = output.decode('ascii').strip(" \n\r")

          if (output.__contains__("\n")):
            #verbose_print("has multiline output w/out \\r")
            retr_output_buffer = output.replace("\n", "\r\n")
            #verbose_print("fresh output buffer: " + str(retr_output_buffer.encode()))
            output_split = retr_output_buffer.split("\r\n", 1)
            output = output_split[0].strip(" \r\n")
            retr_output_buffer = output_split[1].lstrip(" \r\n")
            #verbose_print("3 output: " + str(output.encode()) + "    output_buffer: " + str(retr_output_buffer.encode()))
        except EOFError:
          output = ""
        except ConnectionResetError:
          telnet_list[cur_client_num] = None
          output = ""
        if len(output) <= 0 and (expected != "~" or cur_client_num != client_num):
          break
        if expected == "~":
          expected = ""

      if (is_creating_pasv) and cur_client_num == client_num:
        if len(output) > 0:
          output_split_arr = output.split(",")
          split_len = len(output_split_arr)
          port_part_1 = output_split_arr[split_len - 2].strip(" \r\n()$+*")
          port_part_2 = output_split_arr[split_len - 1].strip(" \r\n()$+*")
          pasv_ports[client_num] = int(port_part_1) * 256 + int(port_part_2)
        else:
          #verbose_print("pasv did not generate proper port output")
          is_creating_pasv = False

      line_matched, repeat_regex, repeat_regexes_left, can_read_next_expected, matched_zero = attempt_regex(expected, output, repeat_regex, repeat_regexes_left)

      if repeat_regex == "" or (line_matched != True and can_read_next_expected):
        repeat_regex = ""
        repeat_regexes_left = 0
        expected = expected_file.readline().rstrip(" \n\r")
        if expected == "~":
          expected = ""
      #else:
        #verbose_print("repeat regex preventing read of next expected")

      line_matched = (output == expected)

      if not line_matched:
        line_matched, repeat_regex, repeat_regexes_left, can_read_next_expected, matched_zero = attempt_regex(expected, output, repeat_regex, repeat_regexes_left)
        if matched_zero:
          #verbose_print("matched zero times, w/ regex: " + repeat_regex + " so reading next expected")
          repeat_regex = ""
          repeat_regexes_left = 0
          expected = expected_file.readline().rstrip(" \n\r")
          if expected == "~":
            expected = ""

          line_matched = (output == expected)


      if not line_matched:
        print("Testcase " + testcase_name + " [Fail]")
        verbose_print("failed at line" + str(line_num))
      if not line_matched or args.linesall:
        print("Command: " + line_str.rstrip(" \n"))
        verbose_print("Expected: " + expected)
        verbose_print("Actual: " + output)

      is_test_passed &= line_matched

      if output == "":
        break

    cur_client_num += 1

  return is_test_passed, retr_output_buffer

def run_test(input_name):
    input_name = input_name.strip("./")
    output_name = input_name.replace('input', 'output')
    testcase_name = input_name.replace(TEST_CASES_PATH, "").replace(".txt", "").replace("test_input_", "")

    #print("-- Start Test {" + testcase_name + "}")

    test_case_file = open("./" + input_name, "r")
    expected_file = open("./" + output_name, "r")

    conf_file_name = ''
    telnet_list = []
    pasv_ports = []

    is_test_passed = True
    line_num = 0
    proc = None
    retr_output_buffer = ""
    for line in test_case_file:
      line_num += 1
      line_str = line

      if line_str == '' or line_str == '\n':
        #verbose_print('skipping blank line')
        continue

      if conf_file_name == '':
        conf_file_name = line_str.rstrip()
        # You implementation starts from here. You are free to change the structure of the code.
        # You can add new functions, classes, or python files. But, the behavior of your program should be consistent to the
        # requirements in the handout and what the skeleton code implies.
        # TODO (1) Change the line below to get the conf file from the first line of the test case file
        configurationFile = "testing_environment/configurations/" + conf_file_name
        executeLine = './bin/' + args.binary + ' -c ' + configurationFile + " -D"

        f = open(configurationFile)
        config_port_val = 0
        for config_lines in f:
          split = config_lines.split("=", 1)
          var_name = split[0].strip(" \n\r\t")
          if var_name == "PORT" and len(split) > 1:
            config_port_val = int(split[1].strip(" \n\"\r\t"))
            break
        f.close()
        #verbose_print("Config PORT: " + str(config_port_val))

        os.system("rm -rf " + TEMP_DIRECTORY_PATH + " 2> /dev/null; mkdir -p " + TEMP_DIRECTORY_PATH)

        # Runs the BFTPD server as a subprocess.
        proc = subprocess.Popen(executeLine, shell=True)
        time.sleep(2)
        if proc.poll() != None:
            print("BFTPD failed to start, try changing your port")
            exit(2)

        continue

      split = line_str.split(':')
      client_num = int(split[0]) - 1
      input_data = split[1].replace('\n', '\r\n')

      for i in range(-1, client_num - len(telnet_list)):
        telnet_list.append(None)
        pasv_ports.append(None)

      command_str = input_data.rstrip(" \n\r").lower()
      is_creating_pasv = command_str == "pasv"
      data_cmd_split = command_str.split(' ')
      is_creating_data = data_cmd_split[0] == "data"

      if (telnet_list[client_num] == None):
        port_to_use = 0
        if is_creating_data:
          #verbose_print("is creating data connection")
          pasv_value_at_port = pasv_ports[int(data_cmd_split[1]) - 1]
          #verbose_print("found_port: " + str(pasv_value_at_port))
          if pasv_value_at_port != None:
            port_to_use = pasv_value_at_port

        if port_to_use == 0:
          port_to_use = config_port_val

        telnet_list[client_num] = Telnet('localhost', port_to_use)

        just_passed_test, retr_output_buffer = verify_output_vs_expected(line_str, is_creating_pasv, telnet_list, pasv_ports, client_num, expected_file, testcase_name, line_num, retr_output_buffer)
        is_test_passed &= just_passed_test

        if not is_test_passed:
          break

        if is_creating_data:
          continue

      try:
        telnet_list[client_num].write(input_data.encode())
      except ConnectionResetError:
        pointless = None
      except BrokenPipeError:
        print("BrokenPipeError caught")
        pointless = None

      just_passed_test, retr_output_buffer = verify_output_vs_expected(line_str, is_creating_pasv, telnet_list, pasv_ports, client_num, expected_file, testcase_name, line_num, retr_output_buffer)
      is_test_passed &= just_passed_test

      if not is_test_passed:
        break

    #remaining_expected = expected_file.readline().rstrip(" \n\r")
    #if len(remaining_expected) > 0:
    #  is_test_passed = False
    #verbose_print("final test for remainder")
    if is_test_passed:
      just_passed_test, retr_output_buffer = verify_output_vs_expected(line_str, is_creating_pasv, telnet_list, pasv_ports, client_num, expected_file, testcase_name, line_num, retr_output_buffer)
      is_test_passed &= just_passed_test


    if is_test_passed:
      verbose_print('Testcase ' + testcase_name + ' [Pass]')
    #output = ''
    #for tn in telnet_list:
    #  if tn != None:
    #    output += tn.read_all().decode()
    #output = output.replace('\r', '').rstrip(" \n\r")
    os.system("rm -rfd " + TEMP_DIRECTORY_PATH + " 2> /dev/null")

    # This kills the bftpd process, and all subprocesses that it created.
    # You must run this before you start another server on the same port
    os.system("ps -u $USER | grep bftpd | grep -v grep | awk '{print $1}' | xargs -r kill -9")

    # returns exit code if there were bugs found
    if is_test_passed:
      return 0
    else:
      return 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="test cases for bftpd server")
    parser.add_argument('-p', action="store", dest="binary")
    parser.add_argument('-f', action="store", dest="file")  # if target test case is not provides, run all tests
    parser.add_argument('-v', action="store_true", dest="verbose")
    parser.add_argument('-a', action="store_true", dest="linesall")

    args = parser.parse_args()

    if not args.binary:
        print("Usage: python framework.py -p binary [-f input_file] [-v verbose]")
        # Exit with code 2, if it can't run the program with the given arguments
        sys.exit(2)

    exit_status = 0

    if args.file:  # Run a single test case
        # Your program can now communicate to the bftpd server.
        # You can use the telnetlib library to interact with it.
        # TODO (2) Run your test here and print the output based on the verbose level.

        exit_status |= run_test(args.file)

        #tn.write(b'quit\r\n') #data)

    else:  # Run all test cases under the testing_environment/testcases folder
        # TODO (3) Run all test cases
        arr = glob(TEST_CASES_PATH + "*input*")
        for f in arr:
            exit_status |= run_test(f)
        #pass

    #verbose_print(str(exit_status))
    sys.exit(exit_status)





