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

object Process extends Yaml {
  /*
   * The Osquery table `processes` lists all running processing
   * on the host machine. It offers an important information
   * summary in relation with other tables.
   */
  val spec: String =
    """
      |author: Dr. Stefan Krusche
      |comment: This node can be associated to STIX v2 Cyber observable 'Process Object'
      |table: processes
      |node: Process
      |label: name
      |entities: Process, Directory, File, User, Group
      |#
      |# Node properties of the 'Process' node
      |#
      |properties:
      |    # Process or thread ID
      |  - pid
      |  - cmdline
      |  - state
      |    # Disk related
      |  - on_disk
      |  - disk_bytes_read
      |  - disk_bytes_written
      |    # Memory related
      |  - resident_size
      |  - total_size
      |  - wired_size
      |    # Time related
      |  - start_time
      |  - system_time
      |  - user_time
      |  - threads
      |  - nice
      |  - is_elevated_token
      |  - elapsed_time
      |  - handle_count
      |  - percent_processor_time
      |  - cpu_type
      |  - cpu_subtype
      |  # Not used
      |  - upid
      |  - uppid
      |edges:
      |  - direction: out
      |    label: cwd
      |    node:
      |      name: Directory
      |      value: cwd
      |  - direction: in
      |    #
      |    # The process is controlled
      |    # by an executed binary file
      |    #
      |    label: ENUM_executes
      |    node:
      |      name: File
      |      label: path
      |      properties:
      |        - type: ENUM_binary
      |  - direction: out
      |    # Process virtual root directory
      |    label: root
      |    node:
      |      name: Directory
      |      value: root
      |  - direction: out
      |    label: parent
      |    node:
      |      name: Process
      |      pid: parent
      |  - direction: out
      |    label: pgroup
      |    node:
      |      name: Group
      |      value: pgroup
      |  - direction: out
      |    #
      |    # The connection to the currently logged in user
      |    # is made via the pid
      |    #
      |    label: uid
      |    node:
      |      name: User
      |      value: uid
      |  - direction: out
      |    label: gid
      |    node:
      |      name: Group
      |      value: gid
      |  - direction: out
      |    label: euid
      |    node:
      |      name: User
      |      value: euid
      |  - direction: out
      |    label: egid
      |    node:
      |      name: Group
      |      value: egid
      |  - direction: out
      |    label: suid
      |    node:
      |      name: User
      |      value: suid
      |  - direction: out
      |    label: sgid
      |    node:
      |      name: Group
      |      value: sgid
      |""".stripMargin

  def main(args:Array[String]):Unit = {

    val json = fromStr(spec)
    println(json)

  }
}
