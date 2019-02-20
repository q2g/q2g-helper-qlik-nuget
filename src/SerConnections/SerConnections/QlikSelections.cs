#region License
/*
Copyright (c) 2018 Konrad Mattheis und Martin Berthold
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#endregion

namespace Ser.Connections
{
    #region Usings
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using NLog;
    using System.Threading.Tasks;
    using Qlik.EngineAPI;
    using Newtonsoft.Json.Linq;
    #endregion

    public class QlikSelections
    {
        #region Logger
        private static Logger logger = LogManager.GetCurrentClassLogger();
        #endregion

        #region Properties
        private IDoc SenseApp { get; set; }
        private QlikDimensions Dimensions { get; set; }
        #endregion

        public QlikSelections(IDoc senseApp)
        {
            SenseApp = senseApp;
            Dimensions = new QlikDimensions(senseApp);
        }

        public async Task<SelectionObject> GetCurrentSelectionAsync()
        {
            try
            {
                var request = JObject.FromObject(new
                {
                    qProp = new
                    {
                        qInfo = new
                        {
                            qType = "CurrentSelection"
                        },
                        qSelectionObjectDef = new { }
                    }
                });

                return await SenseApp.CreateSessionObjectAsync(request)
                .ContinueWith((res) =>
                {
                    return res.Result.GetLayoutAsync<JObject>();
                })
                .Unwrap()
                .ContinueWith<SelectionObject>((res2) =>
                {
                    var ret = res2.Result as dynamic;
                    var jsonObj = ret.qSelectionObject as JObject;
                    var selectionObj = jsonObj.ToObject<SelectionObject>();
                    return selectionObj;
                });
            }
            catch (Exception ex)
            {
                logger.Error(ex, "The filter selection could not be determined.");
                return null;
            }
        }

        public void SelectAllValues(string filterText)
        {
            SelectAllValues(new List<string>() { filterText });
        }

        public void SelectAllValues(List<string> filterTexts)
        {
            try
            {
                var listBoxes = Dimensions.GetListboxList(filterTexts);
                listBoxes?.ForEach(l => l.SelectPossible());
            }
            catch (Exception ex)
            {
                throw new Exception($"The selections could not be executed.", ex);
            }
        }

        public void SelectValues(List<FlatSelection> selections)
        {
            foreach (var flatSel in selections)
                SelectValue(flatSel.Name, flatSel.Value);
        }

        public void ClearSelections(List<string> filterText)
        {
            var listBoxes = Dimensions.GetListboxList(filterText);
            listBoxes?.ForEach(l => l.ClearSelections());
        }

        public void ClearSelections(List<FlatSelection> selections)
        {
            foreach (var flatSel in selections)
            {
                var listBoxes = Dimensions.GetListboxList(new List<string>() { flatSel.Name });
                listBoxes?.ForEach(l => l.ClearSelections());
            }
        }

        public bool SelectValue(string filterText, string match)
        {
            try
            {
                var listBox = Dimensions.GetSelections(filterText);
                var searchResult = listBox.SearchListObjectFor(match);
                if (!searchResult)
                    return false;
                listBox.GetLayout();
                listBox.AcceptListObjectSearchAsync(true).Wait();
                return true;
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"The filter {filterText} coult not set with match {match}.");
                return false;
            }
        }

        public async Task ClearAllSelectionsAsync()
        {
            try
            {
                await SenseApp.AbortModalAsync(false);
            }
            catch (Exception ex)
            {
                logger.Error(ex, "The Qlik selections could not be abort.");
            }

            try
            {
                await SenseApp.ClearAllAsync(true);
            }
            catch (Exception ex)
            {
                throw new Exception("The Qlik selections could not be cleared.", ex);
            }
        }

        private bool RecursiveSelection(List<QlikListbox> listboxes, int start, SelectionGroup group,
                                        List<SelectionGroup> groups, FlatSelection currentSel, string name, bool hasRoot)
        {
            if (currentSel != null)
            {
                if (name != null && name.StartsWith("="))
                    currentSel.AlternativName = SenseApp.EvaluateExAsync(name).Result.qText;
            }

            if (start == listboxes.Count)
            {
                groups.Add(group);
                return false;
            }
            else
            {
                //For Root nodes
                if (hasRoot && currentSel != null)
                {
                    var rootSelectionGroup = new SelectionGroup();
                    if (!String.IsNullOrEmpty(name))
                    {
                        rootSelectionGroup.FlatSelections.Add(currentSel);
                    }
                    else
                        rootSelectionGroup.FlatSelections.Add(currentSel);
                    groups.Add(rootSelectionGroup);
                }
            }

            for (int i = start; i < listboxes.Count; i++)
            {
                var flatSelection = listboxes[i].GetNextSelection();
                listboxes[i].GetLayout();
                if (flatSelection == null)
                {
                    listboxes[i].ResetIndex();
                    return false;
                }

                group.FlatSelections.Add(flatSelection);
                if (RecursiveSelection(listboxes, i + 1, group, groups, flatSelection, name, hasRoot) == false)
                {
                    i--;
                    var newgroup = new SelectionGroup();
                    var lastidx = group.FlatSelections.Count - start;
                    newgroup.FlatSelections.AddRange(group.FlatSelections.Take(group.FlatSelections.Count - lastidx));
                    group = newgroup;
                }
            }

            return true;
        }

        public List<SelectionGroup> DynamicSelections(List<string> filterTexts, string name = null, bool hasRoot = false)
        {
            var groups = new List<SelectionGroup>();
            foreach (var filter in filterTexts)
            {
                var listBoxes = Dimensions.GetListboxList(new List<string> { filter });
                var newgroup = new SelectionGroup();
                RecursiveSelection(listBoxes, 0, newgroup, groups, null, name, hasRoot);
            }

            return groups;
        }
    }
}