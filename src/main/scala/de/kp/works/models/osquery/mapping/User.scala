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

object User extends Yaml {
  /*
   * Osquery specifies a `user_groups` table, which contains
   * a user's `uid` and the associated group's `gid`.
   *
   * Note, this table can be ignored with respect to the
   * Osquery network defined here, as this information is
   * redundant.
   */
  val spec:String =
    """
      |author: Dr. Stefan Krusche
      |comment:
      |table: users
      |node: User
      |entities: User, Directory, Group
      |#
      |# Node properties of the 'User' node
      |#
      |properties:
      |  - uid
      |  - uid_signed
      |  - username
      |  - description
      |  - uuid
      |  - type
      |  - shell
      |  - is_hidden
      |edges:
      |  - direction: out
      |    label: directory
      |    node:
      |      name: Directory
      |      value: directory
      |  - direction: out
      |    label: gid
      |    node:
      |      name: Group
      |      value: gid
      |  - direction: out
      |    label: gid_signed
      |    node:
      |      name: Group
      |      value: gid_signed
      |""".stripMargin
}
