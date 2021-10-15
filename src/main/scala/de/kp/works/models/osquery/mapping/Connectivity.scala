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

object Connectivity extends Yaml {
  /*
   * The Osquery table `connectivity` describes the overall
   * system's network status with a set of flags that e.g.
   * indicate whether any interface is connected via IPv4 or
   * IPv6.
   *
   * From a graph perspective, this table has no added value.
   */
  val spec:String =
    """
      |author: Dr. Stefan Krusche
      |comment:
      |table: connectivity
      |node: Connectivity
      |entities: Connectivity
      |#
      |# Node properties of the 'Connectivity' node
      |#
      |properties:
      |  - disconnected
      |  - ipv4_no_traffic
      |  - ipv6_no_traffic
      |  - ipv4_subnet
      |  - ipv4_local_network
      |  - ipv4_internet
      |  - ipv6_subnet
      |  - ipv6_local_network
      |  - ipv6_internet
      |""".stripMargin

}
