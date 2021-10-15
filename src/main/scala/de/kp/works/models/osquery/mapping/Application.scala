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

object Application extends Yaml {
  /*
   * The Osquery table `background_activities_moderator`
   * can be used to extract user behavior with respect
   * to executing applications.
   *
   * The name of the application is part of the `path`
   * variable and the timestamp `last_execution_time`
   * enables to derive activity profiles.
   */
  val spec:String =
    """
      |author: Dr. Stefan Krusche
      |comment:
      |table: background_activities_moderator
      |node: Application
      |entities: Application, File, User
      |#
      |# Node properties of the 'Application' node
      |#
      |properties:
      |  - last_execution_time
      |edges:
      |  - direction: out
      |    # Path to executed binary (file)
      |    label: path
      |    node:
      |      name: File
      |      value: path
      |  - direction: out
      |    label: sid
      |    node:
      |      name: User
      |      value: sid
      |""".stripMargin
}
