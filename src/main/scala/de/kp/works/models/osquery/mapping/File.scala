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

object File extends Yaml {
  /*
   * The Osquery table `file` delivers the main content
   * to the file based graph. Other file related tables
   * like `authenticode` exist, but this implementation
   * does not take these more detailed data into account.
   */
  val spec: String =
    """
      |author: Dr. Stefan Krusche
      |comment:
      |table: File
      |node: File
      |entities: File, Directory, User, Group, Device
      |#
      |# Node properties of the 'File' node
      |#
      |properties:
      |  - filename
      |  - path
      |  - inode
      |  - mode
      |  - size
      |  - block_size
      |  - atime
      |  - mtime
      |  - ctime
      |  - btime
      |  - hard_links
      |  - symlink
      |  - type
      |  - attributes
      |  - volume_serial
      |  - file_id
      |  - product_version
      |  - bsd_flags
      |  - pid_with_namespace
      |  - mount_namespace_id
      |edges:
      |  - direction: out
      |    # Directory of file(s)
      |    label: directory
      |    node:
      |      name: Directory
      |      value: directory
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
      |    label: device
      |    node:
      |      name: Device
      |      value: device
      |""".stripMargin

  def main(args:Array[String]):Unit = {
    println(fromStr(spec))
  }
}
