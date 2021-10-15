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

object Registry extends Yaml {
  /*
   * The Osquery table `registry` describes a network leaf
   * with no connections to other nodes; however, it can be
   * used to discover the registry behavior
   */
  val spec:String =
    """
      |author: Dr. Stefan Krusche
      |comment:
      |table: registry
      |node: Registry
      |entities: Registry
      |#
      |# Node properties of the 'Registry' node
      |#
      |properties:
      |  - key
      |  - path
      |  - name
      |  - type
      |  - data
      |  - mtime
      |""".stripMargin
}
