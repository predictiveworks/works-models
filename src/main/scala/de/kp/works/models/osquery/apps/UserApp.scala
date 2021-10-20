package de.kp.works.models.osquery.apps
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

import com.google.gson.JsonObject

object UserApp extends BaseApp {

  def transform(json:JsonObject, hostname:String):Unit = {
    /*
     * HOST
     *
     * The current implementation links the host to the
     * user:
     *
     * HOST --> USER --> DIRECTORY
     *               --> GROUP
     *               --> SHELL
     */
    val hostId = buildHashValue(Seq("host", hostname))
    vertices += Vertex(id = hostId, idType = "STRING", label = hostname)

    /*
     * USER
     */
    val userProps = Map(
      DESCRIPTION -> Seq("STRING", json.get(DESCRIPTION).getAsString),
      TYPE        -> Seq("STRING", json.get(TYPE).getAsString),
      UID_SIGNED  -> Seq("LONG", getLongValue(json, UID_SIGNED)),
      USERNAME    -> Seq("STRING", json.get(USERNAME).getAsString),
      UUID        -> Seq("LONG", getLongValue(json, UUID))
      /*
       * IGNORED COLUMNS
       *
       * - is_hidden
       * - pid_with_namespace
       */
    )

    val uid = getLongValue(json, UID)
    val userId = buildHashValue(Seq("user", uid))

    vertices += userVertex(userId, label = uid, props = Some(userProps))
    /*
     * Host -- (has_user) --> User
     */
    edges += buildEdge(hostId, userId, HAS_USER)
    /*
     * USER -- (has_home_dir) --> DIRECTORY
     */
    val directory = json.get(DIRECTORY).getAsString
    val homeId = buildHashValue(Seq("directory", directory))

    vertices += directoryVertex(id = homeId, label = directory)
    edges += buildEdge(userId, homeId, HAS_HOME_DIR)
    /*
     * USER -- (belongs_to) --> GROUP
     */
    val groupProps = Map(GID_SIGNED -> Seq("LONG", getLongValue(json, GID_SIGNED)))

    val gid = getLongValue(json, GID)
    val groupId = buildHashValue(Seq("group", gid))

    vertices += groupVertex(groupId, gid, Some(groupProps))
    edges += buildEdge(userId, groupId, BELONGS_TO)
    /*
     * USER -- (has_shell) --> SHELL
     */

    val shell = json.get(SHELL).getAsString
    val shellId = buildHashValue(Seq("shell", shell))

    vertices += shellVertex(shellId, shell)
    edges += buildEdge(userId, shellId, HAS_SHELL)

  }

}
