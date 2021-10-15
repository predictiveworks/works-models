package de.kp.works.models.osquery.mapping

import de.kp.works.models.Yaml

/*
 * Copyright (c) 2019 - 2021 Dr. Krusche & Partner PartG. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 * @author Stefan Krusche, Dr. Krusche & Partner PartG
 *
 */

object ProcessSocket extends Yaml {
  /*
   * The Osquery table `process_open_sockets` assigns
   * open network sockets to running processes.
   *
   * Combined with Zeek's conn.log, this is of great
   * benefit to understand the origin or destination
   * of network connection in terms executable files.
   */
  val spec:String =
    """
      |author: Dr. Stefan Krusche
      |comment:
      |table: process_open_sockets
      |node: ProcessSocket
      |entities: ProcessSocket, Process, Protocol, Port, IP_Address
      |#
      |# Node properties of the 'ProcessSocket' node
      |#
      |properties:
      |    # The file descriptor number
      |  - fd
      |    # Ths socket handle or inode number
      |  - socket
      |  - state
      |    # The inode number of the network namespace
      |  - net_namespace
      |    # For UNIX sockets (family=AF_UNIX), the domain path
      |  - path
      |edges:
      |  - direction: in
      |    # The controlling process or thread ID
      |    label: pid
      |    node:
      |      name: Process
      |      value: pid
      |  - direction: out
      |    # Transport protocol = TCP, UDP
      |    label: protocol
      |    node:
      |      name: Protocol
      |      value: protocol
      |  - direction: out
      |    label: local_port
      |    node:
      |      name: Port
      |      value: local_port
      |  - direction: out
      |    label: remote_port
      |    node:
      |      name: Port
      |      value: remote_port
      |  - direction: out
      |    # The network protocol = IPv4, IPv6
      |    label: local_address, family
      |    node:
      |      name: IP_Address
      |      value: local_address, family
      |  - direction: out
      |    # The network protocol = IPv4, IPv6
      |    label: remote_address, family
      |    node:
      |      name: IP_Address
      |      value: remote_address, family
      |
      |""".stripMargin
}

/*
+--------------------+--------------+-------+-------+
|           tableName|       colName|colType| osName|
+--------------------+--------------+-------+-------+
|process_open_sockets|            fd|   long|windows|
+--------------------+--------------+-------+-------+

 */