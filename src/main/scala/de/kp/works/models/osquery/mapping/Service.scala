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

class Service extends Yaml {

  val spec:String =
    """
      |author: Dr. Stefan Krusche
      |comment:
      |table: services
      |node: Service
      |entities: Service, File, Process, Account
      |#
      |# Node properties of the 'Service' node
      |#
      |properties:
      |  - name
      |  - description
      |  - service_type
      |  - display_name
      |  - status
      |  - start_type
      |  - win32_exit_code
      |  - service_exit_code
      |edges:
      |  - direction: out
      |    # Process ID of the service
      |    label: pid
      |    node:
      |      name: Process
      |      value: pid
      |  - direction: out
      |    # Path to service executable
      |    label: path
      |    node:
      |      name: File
      |      value: path
      |  - direction: out
      |    # Path to service *.dll
      |    label: module_path
      |    node:
      |      name: File
      |      value: module_path
      |  - direction: out
      |    # The name of the account that the service process
      |    # will be logged on as when it runs.
      |    label: user_account
      |    node:
      |      name: Account
      |      value: user_account
      |""".stripMargin
}
