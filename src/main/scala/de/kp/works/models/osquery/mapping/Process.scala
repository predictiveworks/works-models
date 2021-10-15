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

object Process extends Yaml {

  val spec: String =
    """
      |author: Dr. Stefan Krusche
      |comment: This node can be associated to STIX v2 Cyber observable 'Process Object'
      |table: processes
      |node: Process
      |entities: Process, Directory, File, User, Group
      |#
      |# Node properties of the 'Process' node
      |#
      |properties:
      |  - pid
      |  - name
      |  - cmdline
      |  - state
      |  - on_disk
      |  - wired_size
      |  - resident_size
      |  - total_size
      |  - user_time
      |  - system_time
      |  - disk_bytes_read
      |  - disk_bytes_written
      |  - start_time
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
      |  - direction: out
      |    # Path to executed binary (file)
      |    label: path
      |    node:
      |      name: File
      |      value: path
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
