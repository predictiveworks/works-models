package de.kp.works.models.osquery.mapping
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

import de.kp.works.models.Yaml

object ListeningPorts extends Yaml {
  /*
   * The Osquery table `listening_ports` describes
   * processes with listening (bound) network sockets
   * or ports.
   *
   * Note: this table is similar to `process_open_sockets`
   */
  val spec:String =
    """
      |author: Dr. Stefan Krusche
      |comment:
      |table: listening_ports
      |node: ListeningPort
      |entities: ListeningPort
      |#
      |# Node properties of the 'ListeningPorts' node
      |#
      |properties:
      |    # The file descriptor number
      |  - fd
      |    # Ths socket handle or inode number
      |  - socket
      |    # The inode number of the network namespace
      |  - net_namespace
      |    # For UNIX sockets (family=AF_UNIX), the domain path
      |  - path
      |edges:
      |  - direction: in
      |    # The process or thread ID
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
      |    label: port
      |    node:
      |      name: Port
      |      value: port
      |  - direction: out
      |    # The network protocol = IPv4, IPv6
      |    label: address, family
      |    node:
      |      name: IP_Address
      |      value: address, family
      |      |
      |""".stripMargin

}
