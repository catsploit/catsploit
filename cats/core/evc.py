#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
from cats import *

import pandas as pd
import numpy as np
from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete.CPD import TabularCPD
from pgmpy.inference import VariableElimination
from pgmpy.models import BayesianNetwork


def adjustTable( df ):
    '''

    Parameters
    ----------
    df: pandas.DataFrame
    
    Returns
    -------
    dfcopy: pandas.DataFrame
    '''

    eps = 10**-4  # allowed rounding errors

    
    dfcopy=df.copy()
    
    for col in dfcopy.columns:
        column = dfcopy[col]
        
        nans = column[ column.isna() ]
        valids=column[ column.isna()==False ]
               
        num_nans=nans.shape[0]
        if num_nans > 0:
            adj = (1-valids.sum())/num_nans
            if adj < 0:
                raise Exception("broken table")
                
            dfcopy.loc[ nans.index,col ] = adj
        
        s=dfcopy[col].sum() 
        if s < 1-eps or 1+eps < s:
            raise Exception("broken table")
        
    return dfcopy


def createCPD( df, states ): 
    '''

    Parameters
    ----------
    df: pandas.DataFrame
    states: dict
    
    Returns
    -------
    edges: list of tuple

    cpd: pgmpy.factors.discrete.CPD.TabularCPD
    '''
    
    cols = list(df.columns)
    variable=cols[0]
    variable_states = states[variable]
    variable_card=len(variable_states)
    # if no dependencies
    if len(cols) == 2:
        dfCPD = pd.DataFrame( index=pd.Index( variable_states, name=variable ) ).join( df.set_index(variable) )
        cpd = TabularCPD( variable=variable, variable_card=variable_card, values=dfCPD.values, 
                         state_names={ variable: variable_states } )
        return [], cpd
    # if there is dependencies
    evidence = cols[1:-1]
    evidence_states = { evi:states[evi] for evi in evidence }
    evidence_card  =  [ len(states[evi]) for evi in evidence ] 
    
    columns=pd.MultiIndex.from_product( [ evidence_states[evi] for evi in evidence ], names=evidence )
    dfCPD = pd.DataFrame( index=pd.Index( variable_states, name=variable ), columns=columns )
    for _, row in df.iterrows():
        idx=row[variable]
        col=tuple(row[evidence])
        p  =row.iloc[-1]
        
        dfCPD.loc[idx,col] = p
    dfCPDadjusted=adjustTable(dfCPD)
    cpd = TabularCPD( variable=variable, variable_card=variable_card, values=dfCPDadjusted.values,
                     evidence=evidence,
                     evidence_card=evidence_card,
                     state_names=evidence_states | {variable:variable_states} )
    edges=list()
    for evd in evidence:
        edges.append( (evd, variable) )
    return edges, cpd

 
def dataframeToStates( df ):
    '''

    Parameters
    ----------
    df: pandas.DataFrame
    
    Returns
    -------
    rval: dict { variable: [ possible value ] }
    '''
    
    rval = dict()
    
    for colname in df.columns:
        column = df[colname].dropna()
        rval[colname] = list(column.values)
    
    return rval


def factorToDataFrame( dc ):
    '''

    Parameters
    ----------
    dc: pgmpy.DiscreteFactor
    
    Returns
    -------
    df: pandas.DataFrame
    '''
    variables = dc.variables
    states    = dc.state_names
    
    index = pd.MultiIndex.from_product( [ states[sname] for sname in variables ], names=variables )
    
    values=np.ravel( dc.values )
    
    #pname = "P({states})".format(states=", ".join(variables))
    pname="_P"
    df = pd.DataFrame(index=index, columns=[pname]).reset_index()
    df[pname]=values
    return df


def cpdToDataFrame( cpd ):
    '''
    
    Parameters
    ----------
    cpd: TablularCPD
    
    Returns
    -------
    df: probability table transformed to DataFrame
    '''
    variable = cpd.variable
    evidence = cpd.variables[1:]
    
    var_states = cpd.state_names[variable]
    
    index=pd.Index( var_states, name=variable )
    if len(evidence) == 0:
        columns=["_P"]
        values =cpd.values
    elif len(evidence) == 1:
        eviname=evidence[0]
        columns=pd.Index( cpd.state_names[ eviname ], name=eviname )
        values=cpd.values
    else:
        columns=pd.MultiIndex.from_product( [ cpd.state_names[evi] for evi in evidence ], names=evidence )
        values=np.reshape( np.ravel(cpd.values), ( len(var_states), -1 ) )
    
    df=pd.DataFrame( values, index=index, columns=columns )
    return df


def createBayesianNetworkFromPTables( ptables, states ):
    '''

    Parameters
    ----------
    ptables: array like of pandas.DataFrame
    
    states: dict { stochastic variable:[variable value] }
    
    Returns
    -------
    bn: pgmpy.models.BayesianNetwork

    '''
    edges_all=list()
    nodes_all=list()
    cpds_all =list()

    for dfProbTable in ptables:
        edges, cpd = createCPD(dfProbTable,states)
        node_name=cpd.variable
        nodes_all.append(node_name)
        
        if len(edges) > 0:
            edges_all.extend(edges)
            
        cpds_all.append(cpd)

    bn = BayesianNetwork()
    bn.add_nodes_from(nodes_all)
    for edge in edges_all:
        bn.add_edge( *edge )

    bn.add_cpds(*cpds_all)  
    bn.check_model()

    return bn


class Condition:
    """

    Attributes
    ----------
    vars: set of str
    
    expression: str


    Methods
    -------
    is_empty()
    
    __and__( other )
    
    __or__( other )
    
    __neg__()
    
    Examples
    --------
    c1 = dictToCondition( {"a":1, "b":[2,3]} )
    c2 = dictToCondition( {"x":1 } )
    c3 = c1 & c2
    c4 = c1 | -c2
    c5 = (c1 | c2) & -(c3 & -c4)
    """
    def __init__(self):
        self.vars = None
        self.expression = None
    
    def is_empty(self):
        if self.vars is None:
            return True
        else:
            return False
    
    def _op( self, other, op ):
        rval = Condition()

        if self.is_empty() and other.is_empty():
            return rval

        if self.is_empty():
            return other._op(self, op)

        if other.vars is not None:
            rval.vars = set(self.vars) | set(other.vars)
            rval.expression = f"( {self.expression} ) {op} ( {other.expression} )"
        else:
            rval.vars = set(self.vars)
            rval.expression = self.expression

        return rval
        
    def __and__( self, other ):
        return self._op( other, "&" )
    
    def __or__(self, other ):
        return self._op( other, "|" )
    
    def __neg__(self):
        rval = Condition()
        rval.vars = self.vars
        rval.expression= f"not ({self.expression})"
        return rval
        

def dictToCondition( cond_dict, *, logical_op="&" ):
    '''
    
    Parameters
    ----------
    cond_dict: dict
    logical_op: str, default "&"
    
    Returns
    -------
    c: Condition
    '''
    
    variables = set( cond_dict.keys() )
    
    terms = list()
    for var, value in cond_dict.items():
        var_string=f"`{var}`"
        if type(value) is str or hasattr(value,"__iter__")==False:
            op='=='
            cond_string=repr(value)
        else:
            op='in'
            cond_string=str( list(value) )
        
        term = f"( {var_string} {op} {cond_string} )"
        terms.append(term)
    
    expression = logical_op.join(terms)
    
    rval = Condition()
    rval.vars = variables
    rval.expression = expression
    
    return rval
        
def strToCondition( variables, cond_template ):
    '''
    
    Parameters
    ----------
    variables: array
    cond_template: str
    
    Returns
    -------
    c: Condition
        
    Example
    -------
    c = CONS( ["OS", "port 445"], '{0} in ["Windows 7 SP1", "Windows Server 2008 R2 SP1"] & {1} == "open"' )
    '''    
    
    varstrs = [ f"`{var}`" for var in variables ]
    expression = cond_template.format( *varstrs )
    
    rval = Condition()
    rval.vars = set(variables)
    rval.expression = expression
    
    return rval

def jointProbabilityDistribution( bayesian_network, condition,*,target_vars=None ):
    """

    Parameters
    ----------
    bayesian_network: pgmpy.models.BayesianNetwork
    
    condition: Condition

    target_vars: array like of str
    
    Returns
    -------
    matched: pandas.DataFrame
    """
    
    
    infer = VariableElimination( bayesian_network )
    
    variables = set(condition.vars)
    if target_vars is not None:
        variables |= set(target_vars)
        
    dist = infer.query( variables, show_progress=False )
    
    distDF = factorToDataFrame(dist)
    
    matched = distDF.query( condition.expression, engine="python" )
    
            
    return matched.reset_index(drop=True)


def COND( cond_dict, *, logical_op="&" ):
    '''
    Parameters
    ----------
    cond_dict: dict
    logical_op: str, default "&"
    
    Returns
    -------
    c: Condition
    '''
    return dictToCondition( cond_dict, logical_op=logical_op )

def CONS( variables, cond_template ):
    '''
    
    Parameters
    ----------
    variables: array
    cond_template: str
    
    Returns
    -------
    c: Condition
        
    Example
    -------
    c = CONS( ["OS", "port 445"], '{0} in ["Windows 7 SP1", "Windows Server 2008 R2 SP1"] & {1} == "open"' )
    '''    
    return strToCondition( variables, cond_template )
    
def PROB( condition, bn ):
    """

    Parameters
    ----------
    condition: Condition
    bn: pgmpy.models.BayesianNetwork
    
    Returns
    -------
    p: float
    """
    d = jointProbabilityDistribution( bn, condition )
    return d._P.sum()


def DIST( condition, bn, *, target_vars=None ):
    """
    Parameters
    ----------
    condition: Condition
    bn: pgmpy.models.BayesianNetwork
    target_vars: array of str , default None
    
    Returns
    -------
    rval: pandas.DataFrame
    
    Note
    ----
    """
    dist=jointProbabilityDistribution(bn, condition, target_vars=target_vars)
    
    if target_vars is not None:
        rval=dist.groupby(target_vars).agg({"_P":sum}).reset_index()
    else:
        rval=dist

    return rval


class EvcBase:
    """

    Method
    ------
    name()
    
    condition()
    
    targets()
    
    success_rate(condition)

    Examples
    --------
    refer to evc_bluekeep.py, evc_psexec.py, evc_ssh_login.py
    """
    def name(self):
        """
        Returns
        -------
        name: str
        """
        raise NotImplementedError("Undefined name")

    def condition(self):
        """
        Returns
        -------
        c: evc.Condition
            
        """
        raise NotImplementedError("Undefined condition")
    
    def targets(self):
        """

        Returns
        -------
        vars : array of str
        """
        return None
    
    def success_rate(self, condition):
        """"
        Parameters
        ----------
        condition: pandas.Series

        Returns
        -------
        prob: float
            attack success probability on `condition` ( 0 <= prob <= 1)

        """
        return 1