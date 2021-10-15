package de.kp.works.models.zeek
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

object Conn extends Yaml {
  /*
   * The conn.log file is used for tracking and logging
   * general information regarding TCP, UDP and ICMP traffic.
   *
   * The logged information can be interpreted using flow
   * semantics, with information about the involved host
   * machines and further metadata of the connection.
   *
   * IP_Address (Source) --> Conn --> IP_Address (Destination)
   */
  val spec:String =
    """
      |author: Dr. Stefan Krusche
      |comment:
      |file: Zeek conn.log
      |node: Conn
      |entities: Conn, IP_Address, Port
      |#
      |# Node properties of the 'Conn' node. The property names are compliant
      |# with IgniteGraph. This node represents the connection itself and contains
      |# most of the respective metadata.
      |#
      |properties:
      |  - ts
      |  - duration
      |  - uid
      |  - service
      |    # The transport layer protocol = unknown_transport, tcp, udp, icmp
      |  - proto
      |    # Application protocol sent of the connection
      |  - service
      |  - source_bytes
      |  - destination_bytes
      |  - conn_state
      |    # Flag to indicate whether the connection is originated locally
      |  - source_local
      |    # Flag to indicate whether the connection is responded to locally
      |  - destination_local
      |  - missed_bytes
      |  - source_pkts
      |  - destination_pkts
      |  - source_ip_bytes
      |  - destination_ip_bytes
      |  - source_l2_addr
      |  - destination_l2_addr
      |  - vlan
      |  - inner_vlan
      |  - history
      |    # If this connection was over a tunnel, indicate the uid values for
      |    # any encapsulating parent connections used over the lifetime of this
      |    # inner connection.
      |    #
      |    # In a future version, this properties will be resolved as edges.
      |    #
      |  - tunnel_parents
      |  - speculative_service
      |#
      |# Edges are defined from the source and destination IP, PORT tuples
      |# An IP_Address node represents the source host as well as the destination
      |# host computer and contains the relevant IP address as a single property.
      |#
      |edges:
      |  - direction: in
      |    label: source_ip
      |    # This node (or host) start the connection
      |    node:
      |      name: IP_Address
      |      value: source_ip
      |  - direction: in
      |    label: source_port
      |    node:
      |      name: Port
      |      value: source_port
      |  - direction: out
      |    label: destination_ip
      |    # This node connects to the connection
      |    node:
      |      name: IP_Address
      |      value: destination_ip
      |  - direction: out
      |    label: destination_port
      |    node:
      |      name: Port
      |      value: destination_port
      |""".stripMargin
}
