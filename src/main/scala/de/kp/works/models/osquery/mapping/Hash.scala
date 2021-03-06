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

object Hash extends Yaml {

  val spec:String =
    """
      |author: Dr. Stefan Krusche
      |comment:
      |table: hash
      |node: Hash
      |entities: Hash, Directory, File
      |#
      |# Node properties of the 'Hash' node
      |#
      |properties:
      |  - md5
      |  - sha1
      |  - sha256
      |  - ssdeep
      |  - pid_with_namespace
      |  - mount_namespace_id
      |edges:
      |  - direction: out
      |    # Directory of the associated file
      |    label: directory
      |    node:
      |      name: Directory
      |      value: directory
      |  - direction: out
      |    label: path
      |    node:
      |      name: File
      |      value: path
      |""".stripMargin
}

