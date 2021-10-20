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

object ProcessApp extends BaseApp {

  def transform(json:JsonObject, hostname:String):Unit = {

    /*
     * HOST
     *
     * The current implementation links the host to the
     * process and parent process
     */
    val hostId = buildHashValue(Seq("host", hostname))
    vertices += Vertex(id = hostId, idType = "STRING", label = hostname)
    /*
     * PROCESS
     */
    val pid = getLongValue(json, PID)
    val name = json.get(NAME).getAsString
    val state = json.get(STATE).getAsString

    val processProps = Map(
      NAME -> Seq("STRING", name),

      CMDLINE           -> Seq("STRING", json.get(CMDLINE).getAsString),
      HANDLE_COUNT      -> Seq("LONG", getLongValue(json, HANDLE_COUNT)),
      IS_ELEVATED_TOKEN -> Seq("INT",    getIntValue(json, IS_ELEVATED_TOKEN)),
      NICE              -> Seq("INT",    getIntValue(json, NICE)),
      STATE             -> Seq("STRING", state),
      THREADS           -> Seq("INT",    getIntValue(json, THREADS)),
      /*
       * MEMORY SPACE
       */
      RESIDENT_SIZE -> Seq("LONG", getLongValue(json, RESIDENT_SIZE)),
      WIRED_SIZE    -> Seq("LONG", getLongValue(json, WIRED_SIZE)),
      TOTAL_SIZE    -> Seq("LONG", getLongValue(json, TOTAL_SIZE)),
      /*
       * READ & WRITE BYTES
       */
      ON_DISK            -> Seq("INT",  getIntValue(json, ON_DISK)),
      DISK_BYTES_READ    -> Seq("Long", getLongValue(json, DISK_BYTES_READ)),
      DISK_BYTES_WRITTEN -> Seq("Long", getLongValue(json, DISK_BYTES_WRITTEN)),
      /*
       * TIME RELATED
       */
      ELAPSED_TIME           -> Seq("LONG", getLongValue(json, ELAPSED_TIME)),
      PERCENT_PROCESSOR_TIME -> Seq("LONG", getLongValue(json, PERCENT_PROCESSOR_TIME)),
      START_TIME             -> Seq("LONG", getLongValue(json, START_TIME)),
      SYSTEM_TIME            -> Seq("LONG", getLongValue(json, SYSTEM_TIME)),
      USER_TIME              -> Seq("LONG", getLongValue(json, USER_TIME))
      /*
       * IGNORED COLUMNS
       *
       * - cpu_subtype
       * - cpu_type
       * - upid
       * - uppid
       *
       * - euid
       * - egid
       * - suid
       * - sgid	BIGINT
       */
    )

    val processId = buildHashValue(Seq("process", pid))
    vertices += processVertex(processId, label = pid, Some(processProps))
    /*
     * Host -- (has_process) --> Process
     */
    edges += buildEdge(hostId, processId, HAS_PROCESS)
    /*
     * PARENT PROCESS -- (has_child) --> Process
     */
    val parent = getLongValue(json, PARENT)
    val parentId = buildHashValue(Seq("process", parent))

    vertices += processVertex(parentId, parent)
    edges += buildEdge(processId, parentId, HAS_CHILD)
    /*
     * Host -- (has_process) --> Parent process
     */
    edges += buildEdge(hostId, parentId, HAS_PROCESS)
    /*
     * GROUP <-- (belongs_to) -- Process
     */
    val pgroup = getLongValue(json, PARENT)
    val pgroupId = buildHashValue(Seq("group", pgroup))

    vertices += groupVertex(pgroupId, pgroup)
    edges += buildEdge(processId, pgroupId, BELONGS_TO)
    /*
     * USER <-- (belongs_to) -- Process
     */
    val uid = getLongValue(json, UID)
    val userId = buildHashValue(Seq("user", uid))

    vertices += userVertex(userId, label = uid)
    edges += buildEdge(processId, userId, BELONGS_TO)
    /*
     * Host -- (has_user) --> User
     */
    edges += buildEdge(hostId, userId, HAS_USER)
    /*
     * (USER)GROUP <-- (belongs_to) -- Process
     */
    val gid = getLongValue(json, GID)
    val ugroupId = buildHashValue(Seq("group", gid))

    vertices += groupVertex(ugroupId, gid)
    edges += buildEdge(processId, ugroupId, BELONGS_TO)
    /*
     * FILE <-- (executes) -- Process
     */
    val path = json.get(PATH).getAsString
    val fileId = buildHashValue(Seq("file", path))

    vertices += fileVertex(id = fileId, label = path)
    edges += buildEdge(processId, fileId, EXECUTES)
    /*
     * Host -- (has_file) --> File
     */
    edges += buildEdge(hostId, fileId, HAS_FILE)
    /*
     * DIRECTORY <-- (has_virtual_dir) -- Process
     */
    val root = json.get(ROOT).getAsString
    val rootId = buildHashValue(Seq("directory", root))

    vertices += directoryVertex(id = rootId, label = root)
    edges += buildEdge(processId, rootId, HAS_VIRTUAL_DIR)
    /*
     * DIRECTORY <-- (has_working_dir) -- Process
     */
    val cwd = json.get(CWD).getAsString
    val cwdId = buildHashValue(Seq("directory", cwd))

    vertices += directoryVertex(id = cwdId, label = cwd)
    edges += buildEdge(processId, cwdId, HAS_WORKING_DIR)

  }

}
