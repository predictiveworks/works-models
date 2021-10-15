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

object DNS extends Yaml {
  /*
   * The Osquery table `dns_cache` is not suited to
   * describe DNS (traffic) related data.
   */
  val spec:String =
    """
      |author: Dr. Stefan Krusche
      |comment:
      |table:
      |node: DNS
      |entities: DNS
      |#
      |# Node properties of the 'DNS' node
      |#
      |properties:
      |
      |""".stripMargin
}
