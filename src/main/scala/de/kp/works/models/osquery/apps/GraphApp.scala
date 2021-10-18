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

import com.google.gson.JsonParser
import de.kp.works.models.osquery.Tables

class GraphApp extends BaseApp {

  def transform(event:String):(Seq[Vertex], Seq[Edge]) = {
    /*
     * Deserialize the Fleet or Osquery log event;
     * note, at this stage, the event is normalized
     * already
     */
    val json = JsonParser.parseString(event)
      .getAsJsonObject

    val hostname = json.get(HOSTNAME).getAsString
    /*
     * `name` describes the query name, and in the
     * context of this application also refers to
     * the Osquery table name
     */
    val name = json.get(NAME).getAsString
    name match {
      case Tables.HASH =>
        HashApp.transform(json, hostname)
      case Tables.PROCESS_OPEN_SOCKETS =>
        ConnApp.transform(json, hostname)

      case _ => throw new Exception(s"Table name `$name` is unknown.")
    }

  }
}
