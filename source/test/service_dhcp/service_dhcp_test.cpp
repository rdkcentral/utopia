/**
* Copyright 2024 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/

#include "FopenMock.h"
#include "service_dhcp_mock.h"

FILE *file;

class ServiceDhcpTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        g_syscfgMock = new SyscfgMock();
        g_securewrapperMock = new SecureWrapperMock();
        g_safecLibMock = new SafecLibMock();
        g_utopiaMock = new utopiaMock();
        g_telemetryMock = new telemetryMock();
        g_syseventMock = new SyseventMock();
        g_psmMock = new PsmMock();
        g_messagebusMock = new MessageBusMock();
        g_anscMemoryMock = new AnscMemoryMock();
        g_libnetMock = new LibnetMock();
        g_fileIOMock = new FileIOMock();
        g_fopenMock = new FopenMock();
    }

    void TearDown() override
    {
        delete g_syscfgMock;
        delete g_securewrapperMock;
        delete g_safecLibMock;
        delete g_utopiaMock;
        delete g_telemetryMock;
        delete g_syseventMock;
        delete g_psmMock;
        delete g_messagebusMock;
        delete g_anscMemoryMock;
        delete g_libnetMock;
        delete g_fileIOMock;
        delete g_fopenMock;


        g_syscfgMock = nullptr;
        g_securewrapperMock = nullptr;
        g_safecLibMock = nullptr;
        g_utopiaMock = nullptr;
        g_telemetryMock = nullptr;
        g_syseventMock = nullptr;
        g_psmMock = nullptr;
        g_messagebusMock = nullptr;
        g_anscMemoryMock = nullptr;
        g_libnetMock = nullptr;
        g_fileIOMock = nullptr;
        g_fopenMock = nullptr;
    }
};

void createFile(const char* fname)
{
    if ((file = fopen(fname, "r")))
    {
        fclose(file);
    }
    else
    {
        file = fopen(fname, "w");
        fclose(file);
    }
}

void removeFile(const char* fname)
{
    remove(fname);
}

TEST_F(ServiceDhcpTest, mask2cidr)
{
    char subnetMask[] = "255.255.255.255";
    EXPECT_EQ(32, mask2cidr(subnetMask));
}

TEST_F(ServiceDhcpTest, sysevent_syscfg_init)
{
    FILE *fp1 = NULL;
    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(fp1));

    EXPECT_CALL(*g_messagebusMock, CCSP_Message_Bus_Init(_,_,_,_,_))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _)).WillOnce(Return(0));
    EXPECT_EQ(-1, sysevent_syscfg_init());

}

TEST_F(ServiceDhcpTest, countSetBits)
{
    EXPECT_EQ(8, countSetBits(255));
    EXPECT_EQ(0, countSetBits(139));
}

TEST_F(ServiceDhcpTest, subnet)
{
    char ipv4Addr[] = "192.168.2.10";
    char ipv4Subnet[] = "255.255.255.0";
    char result_subnet[16] = {0};

    subnet(ipv4Addr, ipv4Subnet, result_subnet);

    EXPECT_STREQ(result_subnet, "192.168.2.0");
}

TEST_F(ServiceDhcpTest, wait_till_end_state)
{
    char process_to_wait[] = "process";
    char l_cProcess_Status[16] = {0};
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _)).WillOnce(Return(0));
    wait_till_end_state(process_to_wait);
}

TEST_F(ServiceDhcpTest, compare_files)
{
    char input_file1[] = "file1.txt";
    char input_file2[] = "file2.txt";

    FILE *fp1 = NULL;
    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(fp1));

    EXPECT_EQ(FALSE, compare_files(input_file1, input_file2));
}


TEST_F(ServiceDhcpTest, copy_command_output)
{
    FILE *expectedFd = (FILE *)0xffffffff;
    char expectedOutput[] = "test\n";
    char out[10] = {0};

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(expectedOutput, expectedOutput + strlen(expectedOutput) + 1),
            Return(static_cast<char*>(expectedOutput))
        ));

    copy_command_output(expectedFd, out, sizeof(out));

    EXPECT_STREQ(out, "test");
}

TEST_F(ServiceDhcpTest, print_file)
{
    char to_print_file[] = "file.txt";
    FILE *fp1 = NULL;
    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(fp1));

    print_file(to_print_file);
}

TEST_F(ServiceDhcpTest, copy_file)
{
    char input_file[] = "file1.txt";
    char target_file[] = "file2.txt";

    FILE *fp1 = NULL;
    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(2)
        .WillOnce(Return(fp1))
        .WillOnce(Return(fp1));

    copy_file(input_file, target_file);
}

TEST_F(ServiceDhcpTest, executeCmd)
{
    char cmd[] = "ls";

    int res = executeCmd(cmd);

    EXPECT_EQ(0, res);
}

TEST_F(ServiceDhcpTest, get_device_props)
{
    FILE *fp1 = NULL;
    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(fp1));

    get_device_props();
}

TEST_F(ServiceDhcpTest, print_with_uptime)
{
    struct sysinfo l_sSysInfo;
    struct tm * l_sTimeInfo;
    time_t l_sNowTime;
    int l_iDays, l_iHours, l_iMins, l_iSec;
    char l_cLocalTime[128];
    const char* input = "input";

    print_with_uptime(input);
}

TEST_F(ServiceDhcpTest, _get_shell_output)
{
    char buf[10] = {0};
    FILE *fp = NULL;

    _get_shell_output(fp, buf, sizeof(buf));

    EXPECT_STREQ(buf, "");
}